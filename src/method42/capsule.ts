import { PrivateKey, PublicKey, Hash } from '@bsv/sdk'
import { importAESKey, aesGcmDecrypt } from '../subtle.js'
import { ecdh } from './ecdh.js'
import { computeKeyHash, deriveAESKey, deriveBuyerMaskWithNonce, AES_KEY_LEN } from './kdf.js'
import {
  ErrNilPrivateKey,
  ErrNilPublicKey,
  ErrKeyHashMismatch,
  ErrDecryptionFailed,
  ErrInvalidCiphertext,
} from './errors.js'
import { NONCE_LEN, GCM_TAG_LEN, MIN_CIPHERTEXT_LEN } from './encrypt.js'
import type { DecryptResult } from './encrypt.js'

/**
 * Computes the XOR-masked capsule for a buyer (legacy deterministic version).
 *
 *   capsule = aes_key XOR buyer_mask
 *
 * where:
 *   aes_key    = HKDF(ECDH(D_node, P_node).x, key_hash, "bitfs-file-encryption")
 *   buyer_mask = HKDF(ECDH(D_node, P_buyer).x, key_hash, "bitfs-buyer-mask")
 *
 * WARNING: This function produces a deterministic capsule for a given
 * (D_node, P_buyer, key_hash) tuple. For per-purchase unlinkability,
 * use computeCapsuleWithNonce instead.
 */
export function computeCapsule(
  nodePrivateKey: PrivateKey | null,
  nodePublicKey: PublicKey | null,
  buyerPublicKey: PublicKey | null,
  keyHash: Uint8Array,
): Uint8Array {
  return computeCapsuleWithNonce(nodePrivateKey, nodePublicKey, buyerPublicKey, keyHash, null)
}

/**
 * Computes the XOR-masked capsule for a buyer with an optional per-invoice
 * nonce for capsule unlinkability.
 *
 *   capsule = aes_key XOR buyer_mask
 *
 * where:
 *   aes_key    = HKDF(ECDH(D_node, P_node).x, key_hash, "bitfs-file-encryption")
 *   buyer_mask = HKDF(ECDH(D_node, P_buyer).x, key_hash || nonce, "bitfs-buyer-mask")
 */
export function computeCapsuleWithNonce(
  nodePrivateKey: PrivateKey | null,
  nodePublicKey: PublicKey | null,
  buyerPublicKey: PublicKey | null,
  keyHash: Uint8Array,
  nonce: Uint8Array | null,
): Uint8Array {
  if (keyHash.length !== 32) {
    throw new Error(`method42: keyHash must be 32 bytes, got ${keyHash.length}`)
  }

  // 1. sharedNode = ECDH(D_node, P_node)
  const sharedNode = ecdh(nodePrivateKey, nodePublicKey)

  // 2. aesKey = DeriveAESKey(sharedNode, keyHash)
  const aesKey = deriveAESKey(sharedNode, keyHash)

  // 3. sharedBuyer = ECDH(D_node, P_buyer)
  const sharedBuyer = ecdh(nodePrivateKey, buyerPublicKey)

  // 4. buyerMask = DeriveBuyerMaskWithNonce(sharedBuyer, keyHash, nonce)
  const buyerMask = deriveBuyerMaskWithNonce(sharedBuyer, keyHash, nonce)

  // 5. capsule = xorBytes(aesKey, buyerMask)
  return xorBytes(aesKey, buyerMask)
}

/**
 * Computes SHA256(fileTxID || capsule) for the HTLC hash lock.
 * Binding the capsule hash to the file's transaction ID prevents reuse
 * of a valid capsule across different files.
 */
export function computeCapsuleHash(fileTxID: Uint8Array, capsule: Uint8Array): Uint8Array | null {
  if (fileTxID.length !== 32) {
    return null
  }
  const combined = new Uint8Array(fileTxID.length + capsule.length)
  combined.set(fileTxID)
  combined.set(capsule, fileTxID.length)
  return new Uint8Array(Hash.sha256(Array.from(combined)))
}

/**
 * Decrypts using an XOR-masked capsule obtained via HTLC
 * (legacy deterministic version without nonce).
 *
 * The buyer recovers the AES key as:
 *   buyer_mask = HKDF(ECDH(D_buyer, P_node).x, key_hash, "bitfs-buyer-mask")
 *   aes_key    = capsule XOR buyer_mask
 */
export async function decryptWithCapsule(
  ciphertext: Uint8Array,
  capsule: Uint8Array,
  keyHash: Uint8Array,
  buyerPrivateKey: PrivateKey | null,
  nodePublicKey: PublicKey | null,
): Promise<DecryptResult> {
  return decryptWithCapsuleNonce(ciphertext, capsule, keyHash, buyerPrivateKey, nodePublicKey, null)
}

/**
 * Decrypts using an XOR-masked capsule obtained via HTLC, with an
 * optional per-invoice nonce for capsule unlinkability.
 *
 * The buyer recovers the AES key as:
 *   buyer_mask = HKDF(ECDH(D_buyer, P_node).x, key_hash || nonce, "bitfs-buyer-mask")
 *   aes_key    = capsule XOR buyer_mask
 */
export async function decryptWithCapsuleNonce(
  ciphertext: Uint8Array,
  capsule: Uint8Array,
  keyHash: Uint8Array,
  buyerPrivateKey: PrivateKey | null,
  nodePublicKey: PublicKey | null,
  nonce: Uint8Array | null,
): Promise<DecryptResult> {
  if (!buyerPrivateKey) throw ErrNilPrivateKey
  if (!nodePublicKey) throw ErrNilPublicKey
  if (capsule.length === 0) {
    throw new Error('method42: capsule is empty')
  }
  if (capsule.length !== AES_KEY_LEN) {
    throw new Error(`method42: capsule must be ${AES_KEY_LEN} bytes, got ${capsule.length}`)
  }
  if (keyHash.length !== 32) {
    throw ErrKeyHashMismatch
  }
  if (ciphertext.length < MIN_CIPHERTEXT_LEN) {
    throw ErrInvalidCiphertext
  }

  // 1. sharedBuyer = ECDH(D_buyer, P_node)
  const sharedBuyer = ecdh(buyerPrivateKey, nodePublicKey)

  // 2. buyerMask = DeriveBuyerMaskWithNonce(sharedBuyer, keyHash, nonce)
  const buyerMask = deriveBuyerMaskWithNonce(sharedBuyer, keyHash, nonce)

  // 3. aesKey = capsule XOR buyerMask
  const aesKey = xorBytes(capsule, buyerMask)

  // 4. Decrypt with AES-256-GCM (keyHash as AAD)
  const plaintext = await aesGCMDecryptInternal(ciphertext, aesKey, keyHash)

  // 5. Verify content integrity: SHA256(SHA256(plaintext)) == keyHash
  const computedHash = computeKeyHash(plaintext)
  if (!uint8ArrayEqual(computedHash, keyHash)) {
    throw ErrKeyHashMismatch
  }

  return { plaintext, keyHash: computedHash }
}

// --- Internal helpers ---

/** XORs two Uint8Arrays of equal length. */
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) {
    throw new Error('method42: xorBytes called with mismatched lengths')
  }
  const out = new Uint8Array(a.length)
  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i]
  }
  return out
}

/** Compares two Uint8Arrays for equality. */
function uint8ArrayEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

/** AES-GCM decrypt (duplicated here to avoid circular dependency with encrypt.ts). */
async function aesGCMDecryptInternal(ciphertext: Uint8Array, key: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  if (ciphertext.length < MIN_CIPHERTEXT_LEN) {
    throw ErrInvalidCiphertext
  }

  const nonceBytes = ciphertext.slice(0, NONCE_LEN)
  const encrypted = ciphertext.slice(NONCE_LEN)

  const cryptoKey = await importAESKey(key, ['decrypt'])

  try {
    const decrypted = await aesGcmDecrypt(cryptoKey, encrypted, nonceBytes, aad)
    return new Uint8Array(decrypted)
  } catch {
    throw ErrDecryptionFailed
  }
}
