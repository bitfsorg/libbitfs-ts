import { Hash } from '@bsv/sdk'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { ErrHKDFFailure } from './errors.js'

/** HKDF info string for file content encryption key derivation. */
export const HKDF_INFO = 'bitfs-file-encryption'

/** HKDF info string for buyer mask derivation in paid content flow. */
export const HKDF_BUYER_MASK_INFO = 'bitfs-buyer-mask'

/** HKDF info string for PRIVATE mode metadata encryption. */
export const HKDF_METADATA_INFO = 'bitfs-metadata-encryption'

/** Length of the derived AES-256 key in bytes. */
export const AES_KEY_LEN = 32

/** Length of the random salt for metadata key derivation. */
export const METADATA_SALT_LEN = 16

/** Length of SHA-256 hash output. */
export const HASH_SIZE = 32

/**
 * Computes the double-SHA256 content commitment.
 * Returns SHA256(SHA256(plaintext)), 32 bytes.
 *
 * Serves dual purpose:
 * 1. Salt parameter for HKDF key derivation
 * 2. Content integrity commitment (verified after decryption)
 */
export function computeKeyHash(plaintext: Uint8Array): Uint8Array {
  const first = Hash.sha256(Array.from(plaintext))
  const second = Hash.sha256(first)
  return new Uint8Array(second)
}

/**
 * Derives a 32-byte AES-256 key using HKDF-SHA256.
 *
 * The derivation is DETERMINISTIC: the same (sharedSecretX, keyHash) pair
 * always produces the same AES key.
 *
 * HKDF parameters:
 * - IKM  = sharedSecretX
 * - Salt = keyHash
 * - Info = "bitfs-file-encryption"
 * - Len  = 32 (AES-256)
 */
export function deriveAESKey(sharedSecretX: Uint8Array, keyHash: Uint8Array): Uint8Array {
  if (sharedSecretX.length === 0) {
    throw new Error(`${ErrHKDFFailure.message}: shared secret is empty`)
  }
  if (keyHash.length !== 32) {
    throw new Error(`${ErrHKDFFailure.message}: key hash must be 32 bytes, got ${keyHash.length}`)
  }

  return hkdf(sha256, sharedSecretX, keyHash, HKDF_INFO, AES_KEY_LEN)
}

/**
 * Derives a 32-byte AES-256 key for PRIVATE mode metadata encryption,
 * using a random 16-byte salt.
 *
 * Returns [key, salt]. The salt MUST be stored as a prefix of EncPayload
 * so that the owner can re-derive the same key during decryption.
 */
export function deriveMetadataKey(sharedSecretX: Uint8Array): { key: Uint8Array; salt: Uint8Array } {
  const salt = new Uint8Array(METADATA_SALT_LEN)
  crypto.getRandomValues(salt)
  const key = deriveMetadataKeyWithSalt(sharedSecretX, salt)
  return { key, salt }
}

/**
 * Derives a 32-byte AES-256 key for PRIVATE mode metadata encryption
 * using a provided salt. Used during decryption when the salt is read
 * from the EncPayload prefix.
 */
export function deriveMetadataKeyWithSalt(sharedSecretX: Uint8Array, salt: Uint8Array): Uint8Array {
  if (sharedSecretX.length === 0) {
    throw new Error(`${ErrHKDFFailure.message}: shared secret is empty`)
  }
  if (salt.length !== METADATA_SALT_LEN) {
    throw new Error(`${ErrHKDFFailure.message}: metadata salt must be ${METADATA_SALT_LEN} bytes, got ${salt.length}`)
  }

  return hkdf(sha256, sharedSecretX, salt, HKDF_METADATA_INFO, AES_KEY_LEN)
}

/**
 * Derives a 32-byte buyer mask using HKDF-SHA256 (legacy deterministic version).
 * Used in the paid content flow: capsule = aes_key XOR buyer_mask.
 */
export function deriveBuyerMask(sharedSecretX: Uint8Array, keyHash: Uint8Array): Uint8Array {
  return deriveBuyerMaskWithNonce(sharedSecretX, keyHash, null)
}

/**
 * Derives a 32-byte buyer mask using HKDF-SHA256, with an optional per-invoice
 * nonce for capsule unlinkability.
 *
 * When nonce is non-null, it is appended to the HKDF salt (keyHash || nonce),
 * making each capsule unique even for repeat purchases of the same file by the
 * same buyer.
 *
 * HKDF parameters:
 * - IKM  = sharedSecretX
 * - Salt = keyHash (if nonce is null) or keyHash || nonce
 * - Info = "bitfs-buyer-mask"
 * - Len  = 32 (AES-256)
 */
export function deriveBuyerMaskWithNonce(
  sharedSecretX: Uint8Array,
  keyHash: Uint8Array,
  nonce: Uint8Array | null,
): Uint8Array {
  if (sharedSecretX.length === 0) {
    throw new Error(`${ErrHKDFFailure.message}: shared secret is empty`)
  }
  if (keyHash.length !== 32) {
    throw new Error(`${ErrHKDFFailure.message}: key hash must be 32 bytes, got ${keyHash.length}`)
  }

  // Build HKDF salt: keyHash alone (legacy) or keyHash || nonce (unlinkable).
  let salt: Uint8Array
  if (nonce && nonce.length > 0) {
    salt = new Uint8Array(keyHash.length + nonce.length)
    salt.set(keyHash)
    salt.set(nonce, keyHash.length)
  } else {
    salt = keyHash
  }

  return hkdf(sha256, sharedSecretX, salt, HKDF_BUYER_MASK_INFO, AES_KEY_LEN)
}
