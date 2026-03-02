import { PrivateKey, PublicKey } from '@bsv/sdk'
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
  ErrKeyHashMismatch,
} from './errors.js'
import { timingSafeEqual } from '../util.js'
import { aesGCMEncrypt, aesGCMDecrypt, NONCE_LEN, GCM_TAG_LEN, MIN_CIPHERTEXT_LEN } from './aes.js'

// Re-export AES-GCM constants for downstream consumers (capsule.ts, index.ts)
export { NONCE_LEN, GCM_TAG_LEN, MIN_CIPHERTEXT_LEN }

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
  if (!publicKey) throw ErrNilPublicKey()

  // Step 1: Compute key_hash = SHA256(SHA256(plaintext))
  const keyHash = computeKeyHash(plaintext)

  // Step 2: Get effective private key based on access mode
  const effKey = effectivePrivateKey(access, privateKey)

  // Step 3: ECDH to get shared secret x-coordinate
  const sharedX = ecdh(effKey, publicKey)

  // Step 4: Derive AES key via HKDF-SHA256
  const aesKey = deriveAESKey(sharedX, keyHash)

  try {
    // Step 5: Encrypt with AES-256-GCM (keyHash as AAD)
    const ciphertext = await aesGCMEncrypt(plaintext, aesKey, keyHash)

    return { ciphertext, keyHash }
  } finally {
    // S-04: Zero intermediate key material
    sharedX.fill(0)
    aesKey.fill(0)
  }
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
  if (!publicKey) throw ErrNilPublicKey()
  if (keyHash.length !== 32) throw ErrKeyHashMismatch()

  // Get effective private key based on access mode
  const effKey = effectivePrivateKey(access, privateKey)

  // ECDH to get shared secret x-coordinate
  const sharedX = ecdh(effKey, publicKey)

  // Derive AES key via HKDF-SHA256
  const aesKey = deriveAESKey(sharedX, keyHash)

  try {
    // Decrypt with AES-256-GCM (keyHash as AAD)
    const plaintext = await aesGCMDecrypt(ciphertext, aesKey, keyHash)

    // Verify content integrity: SHA256(SHA256(plaintext)) == keyHash
    const computedHash = computeKeyHash(plaintext)
    if (!timingSafeEqual(computedHash, keyHash)) {
      throw ErrKeyHashMismatch()
    }

    return { plaintext, keyHash: computedHash }
  } finally {
    // S-04: Zero intermediate key material
    sharedX.fill(0)
    aesKey.fill(0)
  }
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
  if (!privateKey) throw ErrNilPrivateKey()
  if (!publicKey) throw ErrNilPublicKey()

  const sharedX = ecdh(privateKey, publicKey)
  const { key: metaKey, salt } = deriveMetadataKey(sharedX)

  try {
    const ciphertext = await aesGCMEncrypt(tlvPayload, metaKey, salt)

    // EncPayload = salt(16B) || nonce(12B) || ciphertext || tag(16B)
    const encPayload = new Uint8Array(METADATA_SALT_LEN + ciphertext.length)
    encPayload.set(salt)
    encPayload.set(ciphertext, METADATA_SALT_LEN)
    return encPayload
  } finally {
    // S-04: Zero intermediate key material
    sharedX.fill(0)
    metaKey.fill(0)
  }
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
  if (!privateKey) throw ErrNilPrivateKey()
  if (!publicKey) throw ErrNilPublicKey()
  if (encPayload.length < MIN_ENC_PAYLOAD_LEN) {
    throw ErrInvalidCiphertext()
  }

  const salt = encPayload.slice(0, METADATA_SALT_LEN)
  const ciphertext = encPayload.slice(METADATA_SALT_LEN)

  const sharedX = ecdh(privateKey, publicKey)
  const metaKey = deriveMetadataKeyWithSalt(sharedX, salt)

  try {
    return await aesGCMDecrypt(ciphertext, metaKey, salt)
  } finally {
    // S-04: Zero intermediate key material
    sharedX.fill(0)
    metaKey.fill(0)
  }
}


