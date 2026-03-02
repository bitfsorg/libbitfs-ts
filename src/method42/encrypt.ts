import { PrivateKey, PublicKey } from '@bsv/sdk'
import { importAESKey, aesGcmEncrypt, aesGcmDecrypt } from '../subtle.js'
import { Access, effectivePrivateKey } from './access.js'
import { ecdh } from './ecdh.js'
import {
  computeKeyHash,
  deriveAESKey,
  deriveMetadataKey,
  deriveMetadataKeyWithSalt,
  METADATA_SALT_LEN,
} from './kdf.js'
import {
  ErrNilPublicKey,
  ErrNilPrivateKey,
  ErrInvalidCiphertext,
  ErrDecryptionFailed,
  ErrKeyHashMismatch,
} from './errors.js'

/** Length of the AES-GCM nonce in bytes. */
export const NONCE_LEN = 12

/** Length of the GCM authentication tag in bytes. */
export const GCM_TAG_LEN = 16

/** Minimum valid ciphertext length (nonce + tag). */
export const MIN_CIPHERTEXT_LEN = NONCE_LEN + GCM_TAG_LEN

/** Minimum valid EncPayload length (salt + nonce + tag). */
export const MIN_ENC_PAYLOAD_LEN = METADATA_SALT_LEN + NONCE_LEN + GCM_TAG_LEN

/** Result of an encryption operation. */
export interface EncryptResult {
  /** nonce(12B) || AES-256-GCM(plaintext) || tag(16B) */
  ciphertext: Uint8Array
  /** SHA256(SHA256(plaintext)), 32 bytes */
  keyHash: Uint8Array
}

/** Result of a decryption operation. */
export interface DecryptResult {
  /** The decrypted content. */
  plaintext: Uint8Array
  /** Recomputed SHA256(SHA256(plaintext)) for verification. */
  keyHash: Uint8Array
}

/**
 * Encrypts plaintext using Method 42.
 *
 * Process:
 * 1. Computes key_hash = SHA256(SHA256(plaintext))
 * 2. Performs ECDH(D_node, P_node) to get shared secret
 * 3. Derives AES key via HKDF-SHA256
 * 4. Encrypts with AES-256-GCM (random 12-byte nonce)
 */
export async function encrypt(
  plaintext: Uint8Array,
  privateKey: PrivateKey | null,
  publicKey: PublicKey | null,
  access: Access,
): Promise<EncryptResult> {
  if (!publicKey) throw ErrNilPublicKey

  // Step 1: Compute key_hash = SHA256(SHA256(plaintext))
  const keyHash = computeKeyHash(plaintext)

  // Step 2: Get effective private key based on access mode
  const effKey = effectivePrivateKey(access, privateKey)

  // Step 3: ECDH to get shared secret x-coordinate
  const sharedX = ecdh(effKey, publicKey)

  // Step 4: Derive AES key via HKDF-SHA256
  const aesKey = deriveAESKey(sharedX, keyHash)

  // Step 5: Encrypt with AES-256-GCM (keyHash as AAD)
  const ciphertext = await aesGCMEncrypt(plaintext, aesKey, keyHash)

  return { ciphertext, keyHash }
}

/**
 * Decrypts ciphertext using Method 42.
 *
 * Process:
 * 1. Performs ECDH to recover shared secret
 * 2. Derives AES key using provided key_hash
 * 3. Decrypts with AES-256-GCM
 * 4. Verifies SHA256(SHA256(plaintext)) == key_hash
 */
export async function decrypt(
  ciphertext: Uint8Array,
  privateKey: PrivateKey | null,
  publicKey: PublicKey | null,
  keyHash: Uint8Array,
  access: Access,
): Promise<DecryptResult> {
  if (!publicKey) throw ErrNilPublicKey
  if (keyHash.length !== 32) throw ErrKeyHashMismatch

  // Get effective private key based on access mode
  const effKey = effectivePrivateKey(access, privateKey)

  // ECDH to get shared secret x-coordinate
  const sharedX = ecdh(effKey, publicKey)

  // Derive AES key via HKDF-SHA256
  const aesKey = deriveAESKey(sharedX, keyHash)

  // Decrypt with AES-256-GCM (keyHash as AAD)
  const plaintext = await aesGCMDecrypt(ciphertext, aesKey, keyHash)

  // Verify content integrity: SHA256(SHA256(plaintext)) == keyHash
  const computedHash = computeKeyHash(plaintext)
  if (!uint8ArrayEqual(computedHash, keyHash)) {
    throw ErrKeyHashMismatch
  }

  return { plaintext, keyHash: computedHash }
}

/**
 * Re-encrypts content from one access mode to another.
 * Decrypts with fromAccess parameters, then encrypts with toAccess parameters.
 */
export async function reEncrypt(
  ciphertext: Uint8Array,
  privateKey: PrivateKey | null,
  publicKey: PublicKey | null,
  keyHash: Uint8Array,
  fromAccess: Access,
  toAccess: Access,
): Promise<EncryptResult> {
  // Decrypt with old access mode
  const result = await decrypt(ciphertext, privateKey, publicKey, keyHash, fromAccess)
  // Encrypt with new access mode
  return encrypt(result.plaintext, privateKey, publicKey, toAccess)
}

/**
 * Encrypts a TLV metadata payload for PRIVATE mode.
 * Uses a random 16-byte salt for HKDF key derivation.
 * Output format: salt(16B) || nonce(12B) || AES-GCM(tlvPayload) || tag(16B).
 */
export async function encryptMetadata(
  tlvPayload: Uint8Array,
  privateKey: PrivateKey | null,
  publicKey: PublicKey | null,
): Promise<Uint8Array> {
  if (!privateKey) throw ErrNilPrivateKey
  if (!publicKey) throw ErrNilPublicKey

  const sharedX = ecdh(privateKey, publicKey)
  const { key: metaKey, salt } = deriveMetadataKey(sharedX)
  const ciphertext = await aesGCMEncrypt(tlvPayload, metaKey, salt)

  // EncPayload = salt(16B) || nonce(12B) || ciphertext || tag(16B)
  const encPayload = new Uint8Array(METADATA_SALT_LEN + ciphertext.length)
  encPayload.set(salt)
  encPayload.set(ciphertext, METADATA_SALT_LEN)
  return encPayload
}

/**
 * Decrypts a PRIVATE mode EncPayload back to TLV bytes.
 * Input format: salt(16B) || nonce(12B) || AES-GCM(tlvPayload) || tag(16B).
 */
export async function decryptMetadata(
  encPayload: Uint8Array,
  privateKey: PrivateKey | null,
  publicKey: PublicKey | null,
): Promise<Uint8Array> {
  if (!privateKey) throw ErrNilPrivateKey
  if (!publicKey) throw ErrNilPublicKey
  if (encPayload.length < MIN_ENC_PAYLOAD_LEN) {
    throw ErrInvalidCiphertext
  }

  const salt = encPayload.slice(0, METADATA_SALT_LEN)
  const ciphertext = encPayload.slice(METADATA_SALT_LEN)

  const sharedX = ecdh(privateKey, publicKey)
  const metaKey = deriveMetadataKeyWithSalt(sharedX, salt)
  return aesGCMDecrypt(ciphertext, metaKey, salt)
}

// --- Internal helpers ---

/**
 * Encrypts plaintext with AES-256-GCM.
 * AAD binds the ciphertext to a specific context.
 * Returns nonce(12B) || ciphertext || tag(16B).
 */
async function aesGCMEncrypt(plaintext: Uint8Array, key: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  const nonce = new Uint8Array(NONCE_LEN)
  crypto.getRandomValues(nonce)

  const cryptoKey = await importAESKey(key, ['encrypt'])
  const encrypted = await aesGcmEncrypt(cryptoKey, plaintext, nonce, aad)

  // Output format: nonce(12B) || ciphertext || GCM tag(16B)
  // SubtleCrypto appends the 16-byte tag to the ciphertext automatically
  const result = new Uint8Array(NONCE_LEN + encrypted.byteLength)
  result.set(nonce)
  result.set(new Uint8Array(encrypted), NONCE_LEN)
  return result
}

/**
 * Decrypts AES-256-GCM ciphertext.
 * AAD must match the AAD used during encryption.
 * Input format: nonce(12B) || ciphertext || tag(16B).
 */
async function aesGCMDecrypt(ciphertext: Uint8Array, key: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  if (ciphertext.length < MIN_CIPHERTEXT_LEN) {
    throw ErrInvalidCiphertext
  }

  const nonce = ciphertext.slice(0, NONCE_LEN)
  const encrypted = ciphertext.slice(NONCE_LEN)

  const cryptoKey = await importAESKey(key, ['decrypt'])

  try {
    const decrypted = await aesGcmDecrypt(cryptoKey, encrypted, nonce, aad)
    return new Uint8Array(decrypted)
  } catch {
    throw ErrDecryptionFailed
  }
}

/** Compares two Uint8Arrays for equality. */
function uint8ArrayEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}
