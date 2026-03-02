/**
 * Shared AES-256-GCM encrypt/decrypt helpers for Method 42.
 *
 * Extracted from encrypt.ts and capsule.ts to eliminate duplication.
 * These are internal helpers — not re-exported from the package index.
 */

import { importAESKey, aesGcmEncrypt, aesGcmDecrypt } from '../subtle.js'
import { ErrInvalidCiphertext, ErrDecryptionFailed } from './errors.js'

/** Length of the AES-GCM nonce in bytes. */
export const NONCE_LEN = 12

/** Length of the GCM authentication tag in bytes. */
export const GCM_TAG_LEN = 16

/** Minimum valid ciphertext length (nonce + tag). */
export const MIN_CIPHERTEXT_LEN = NONCE_LEN + GCM_TAG_LEN

/**
 * Encrypts plaintext with AES-256-GCM.
 * AAD binds the ciphertext to a specific context.
 * Returns nonce(12B) || ciphertext || tag(16B).
 */
export async function aesGCMEncrypt(plaintext: Uint8Array, key: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
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
export async function aesGCMDecrypt(ciphertext: Uint8Array, key: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  if (ciphertext.length < MIN_CIPHERTEXT_LEN) {
    throw ErrInvalidCiphertext()
  }

  const nonce = ciphertext.slice(0, NONCE_LEN)
  const encrypted = ciphertext.slice(NONCE_LEN)

  const cryptoKey = await importAESKey(key, ['decrypt'])

  try {
    const decrypted = await aesGcmDecrypt(cryptoKey, encrypted, nonce, aad)
    return new Uint8Array(decrypted)
  } catch {
    throw ErrDecryptionFailed()
  }
}
