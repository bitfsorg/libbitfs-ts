/**
 * Seed generation and encryption for the BitFS HD wallet.
 *
 * BIP39 mnemonic generation and validation, seed derivation (PBKDF2-SHA512),
 * and seed encryption using Argon2id + AES-256-GCM.
 *
 * Encryption format: salt(16B) || nonce(12B) || AES-GCM(seed || SHA256(seed)[:4])
 */

import { Mnemonic } from '@bsv/sdk'
import { importAESKey, aesGcmEncrypt, aesGcmDecrypt } from '../subtle.js'
import { sha256 } from '@noble/hashes/sha2'
import { argon2id } from '@noble/hashes/argon2'
import {
  InvalidEntropyError,
  InvalidMnemonicError,
  InvalidSeedError,
  DecryptionFailedError,
  ChecksumMismatchError,
} from './errors.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Entropy bits for a 12-word BIP39 mnemonic. */
export const MNEMONIC_12_WORDS = 128

/** Entropy bits for a 24-word BIP39 mnemonic. */
export const MNEMONIC_24_WORDS = 256

/** Argon2id time cost (iterations). */
export const ARGON2_TIME = 10

/** Argon2id memory cost in KiB (256 MB). */
export const ARGON2_MEMORY = 262144 // 256 * 1024

/** Argon2id parallelism (threads). */
export const ARGON2_PARALLELISM = 1

/** Argon2id output key length in bytes. */
export const ARGON2_KEY_LEN = 32

/** Salt length in bytes. */
export const SALT_LEN = 16

/** AES-GCM nonce length in bytes. */
export const NONCE_LEN = 12

/** Checksum length in bytes (SHA256(seed)[:4]). */
export const CHECKSUM_LEN = 4

// ---------------------------------------------------------------------------
// Mnemonic
// ---------------------------------------------------------------------------

/**
 * Generate a new BIP39 mnemonic with the specified entropy bits.
 *
 * @param entropyBits - 128 for 12 words, 256 for 24 words
 * @returns The mnemonic phrase as a space-separated string
 */
export function generateMnemonic(entropyBits: number = MNEMONIC_12_WORDS): string {
  if (entropyBits !== MNEMONIC_12_WORDS && entropyBits !== MNEMONIC_24_WORDS) {
    throw new InvalidEntropyError()
  }
  const m = Mnemonic.fromRandom(entropyBits)
  return m.toString()
}

/**
 * Validate a BIP39 mnemonic phrase.
 *
 * @param mnemonic - The mnemonic string to validate
 * @returns true if valid, false otherwise
 */
export function validateMnemonic(mnemonic: string): boolean {
  if (!mnemonic || mnemonic.trim() === '') return false
  try {
    const m = new Mnemonic(mnemonic)
    return m.check()
  } catch {
    return false
  }
}

/**
 * Derive a 64-byte BIP39 seed from mnemonic + optional passphrase.
 *
 * seed = PBKDF2(mnemonic, "mnemonic"+passphrase, 2048, 64, SHA512)
 *
 * @param mnemonic - The BIP39 mnemonic phrase
 * @param passphrase - Optional passphrase (can be empty string)
 * @returns 64-byte seed as Uint8Array
 */
export function seedFromMnemonic(mnemonic: string, passphrase: string = ''): Uint8Array {
  if (!validateMnemonic(mnemonic)) {
    throw new InvalidMnemonicError()
  }
  const m = new Mnemonic(mnemonic)
  const seedArray: number[] = m.toSeed(passphrase)
  return new Uint8Array(seedArray)
}

// ---------------------------------------------------------------------------
// Seed Encryption / Decryption
// ---------------------------------------------------------------------------

/**
 * Encrypt the seed with Argon2id + AES-256-GCM.
 *
 * Output format: salt(16B) || nonce(12B) || AES-GCM(argon2id(password,salt), nonce, seed||checksum)
 *
 * The checksum is SHA256(seed)[:4] for verifying correct decryption.
 *
 * @param seed - The seed bytes to encrypt
 * @param password - The password for key derivation
 * @returns The encrypted seed as Uint8Array
 */
export async function encryptSeed(seed: Uint8Array, password: string): Promise<Uint8Array> {
  if (seed.length === 0) {
    throw new InvalidSeedError()
  }

  // Generate random salt
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN))

  // Derive encryption key using Argon2id
  const derivedKey = argon2id(new TextEncoder().encode(password), salt, {
    t: ARGON2_TIME,
    m: ARGON2_MEMORY,
    p: ARGON2_PARALLELISM,
    dkLen: ARGON2_KEY_LEN,
  })

  // Compute checksum: SHA256(seed)[:4]
  const seedHash = sha256(seed)
  const checksum = seedHash.slice(0, CHECKSUM_LEN)

  // Prepare plaintext: seed || checksum
  const plaintext = new Uint8Array(seed.length + CHECKSUM_LEN)
  plaintext.set(seed, 0)
  plaintext.set(checksum, seed.length)

  try {
    // AES-256-GCM encryption using Web Crypto API
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN))
    const cryptoKey = await importAESKey(derivedKey, ['encrypt'])
    const ciphertext = new Uint8Array(
      await aesGcmEncrypt(cryptoKey, plaintext, nonce),
    )

    // Output: salt(16B) || nonce(12B) || ciphertext
    const result = new Uint8Array(SALT_LEN + NONCE_LEN + ciphertext.length)
    result.set(salt, 0)
    result.set(nonce, SALT_LEN)
    result.set(ciphertext, SALT_LEN + NONCE_LEN)

    return result
  } finally {
    // S-04: Zero key material after use
    derivedKey.fill(0)
    plaintext.fill(0)
  }
}

/**
 * Decrypt the seed from the encrypted format.
 *
 * Input format: salt(16B) || nonce(12B) || ciphertext
 *
 * Derives key with Argon2id, decrypts with AES-256-GCM, then verifies
 * the SHA256(seed)[:4] checksum to confirm correct decryption.
 *
 * @param encrypted - The encrypted seed bytes
 * @param password - The password for key derivation
 * @returns The decrypted seed as Uint8Array
 */
export async function decryptSeed(encrypted: Uint8Array, password: string): Promise<Uint8Array> {
  const minLen = SALT_LEN + NONCE_LEN + CHECKSUM_LEN
  if (encrypted.length < minLen) {
    throw new DecryptionFailedError()
  }

  // Parse components
  const salt = encrypted.slice(0, SALT_LEN)
  const nonce = encrypted.slice(SALT_LEN, SALT_LEN + NONCE_LEN)
  const ciphertext = encrypted.slice(SALT_LEN + NONCE_LEN)

  // Derive decryption key using Argon2id with same parameters
  const derivedKey = argon2id(new TextEncoder().encode(password), salt, {
    t: ARGON2_TIME,
    m: ARGON2_MEMORY,
    p: ARGON2_PARALLELISM,
    dkLen: ARGON2_KEY_LEN,
  })

  let plaintext: Uint8Array | undefined
  try {
    // AES-256-GCM decryption
    try {
      const cryptoKey = await importAESKey(derivedKey, ['decrypt'])
      plaintext = new Uint8Array(
        await aesGcmDecrypt(cryptoKey, ciphertext, nonce),
      )
    } catch {
      throw new DecryptionFailedError()
    }

    if (plaintext.length < CHECKSUM_LEN) {
      throw new DecryptionFailedError()
    }

    // Split seed and checksum
    const seed = plaintext.slice(0, plaintext.length - CHECKSUM_LEN)
    const storedChecksum = plaintext.slice(plaintext.length - CHECKSUM_LEN)

    // Verify checksum
    const seedHash = sha256(seed)
    const expectedChecksum = seedHash.slice(0, CHECKSUM_LEN)

    // Constant-time comparison to prevent timing side-channel
    let diff = 0
    for (let i = 0; i < CHECKSUM_LEN; i++) {
      diff |= storedChecksum[i] ^ expectedChecksum[i]
    }
    if (diff !== 0) {
      throw new ChecksumMismatchError()
    }

    return seed
  } finally {
    // S-04: Zero key material after use
    derivedKey.fill(0)
    if (plaintext) plaintext.fill(0)
  }
}
