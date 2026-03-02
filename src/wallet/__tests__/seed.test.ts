import { describe, it, expect } from 'vitest'
import {
  generateMnemonic,
  validateMnemonic,
  seedFromMnemonic,
  encryptSeed,
  decryptSeed,
  MNEMONIC_12_WORDS,
  MNEMONIC_24_WORDS,
  SALT_LEN,
  NONCE_LEN,
  CHECKSUM_LEN,
  InvalidEntropyError,
  InvalidMnemonicError,
  InvalidSeedError,
  DecryptionFailedError,
} from '../index.js'

// ---------------------------------------------------------------------------
// Mnemonic generation
// ---------------------------------------------------------------------------

describe('generateMnemonic', () => {
  it('generates a valid 12-word mnemonic', () => {
    const mnemonic = generateMnemonic(MNEMONIC_12_WORDS)
    const words = mnemonic.split(' ')
    expect(words).toHaveLength(12)
    expect(validateMnemonic(mnemonic)).toBe(true)
  })

  it('generates a valid 24-word mnemonic', () => {
    const mnemonic = generateMnemonic(MNEMONIC_24_WORDS)
    const words = mnemonic.split(' ')
    expect(words).toHaveLength(24)
    expect(validateMnemonic(mnemonic)).toBe(true)
  })

  it('throws InvalidEntropyError for invalid entropy bits', () => {
    expect(() => generateMnemonic(64)).toThrow(InvalidEntropyError)
    expect(() => generateMnemonic(192)).toThrow(InvalidEntropyError)
  })

  it('generates unique mnemonics each time', () => {
    const m1 = generateMnemonic(MNEMONIC_12_WORDS)
    const m2 = generateMnemonic(MNEMONIC_12_WORDS)
    expect(m1).not.toBe(m2)
  })

  it('defaults to 12 words when no argument given', () => {
    const mnemonic = generateMnemonic()
    const words = mnemonic.split(' ')
    expect(words).toHaveLength(12)
  })
})

// ---------------------------------------------------------------------------
// Mnemonic validation
// ---------------------------------------------------------------------------

describe('validateMnemonic', () => {
  it('accepts valid 12-word mnemonic', () => {
    expect(
      validateMnemonic(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      ),
    ).toBe(true)
  })

  it('rejects invalid words', () => {
    expect(
      validateMnemonic(
        'foo bar baz qux quux corge grault garply waldo fred plugh xyzzy',
      ),
    ).toBe(false)
  })

  it('rejects empty string', () => {
    expect(validateMnemonic('')).toBe(false)
  })

  it('rejects partial mnemonic', () => {
    expect(validateMnemonic('abandon abandon')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Seed derivation
// ---------------------------------------------------------------------------

describe('seedFromMnemonic', () => {
  const testMnemonic =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

  it('produces a deterministic 64-byte seed', () => {
    const seed1 = seedFromMnemonic(testMnemonic, '')
    const seed2 = seedFromMnemonic(testMnemonic, '')
    expect(seed1).toHaveLength(64)
    expect(seed1).toEqual(seed2)
  })

  it('produces different seeds with different passphrases', () => {
    const seed1 = seedFromMnemonic(testMnemonic, '')
    const seed2 = seedFromMnemonic(testMnemonic, 'my secret passphrase')
    expect(seed1).not.toEqual(seed2)
  })

  it('throws InvalidMnemonicError for invalid mnemonic', () => {
    expect(() => seedFromMnemonic('invalid mnemonic words here', '')).toThrow(
      InvalidMnemonicError,
    )
  })

  it('defaults passphrase to empty string', () => {
    const seed1 = seedFromMnemonic(testMnemonic)
    const seed2 = seedFromMnemonic(testMnemonic, '')
    expect(seed1).toEqual(seed2)
  })
})

// ---------------------------------------------------------------------------
// Seed encryption / decryption
// ---------------------------------------------------------------------------

describe('encryptSeed / decryptSeed', () => {
  // Argon2id with 64 MB memory is ~1.4s per call, so increase timeout for all crypto tests
  it('round-trips correctly', { timeout: 10_000 }, async () => {
    const seed = new Uint8Array(64)
    for (let i = 0; i < seed.length; i++) seed[i] = i
    const password = 'test-password-123'

    const encrypted = await encryptSeed(seed, password)
    expect(encrypted.length).toBeGreaterThan(seed.length)

    const decrypted = await decryptSeed(encrypted, password)
    expect(decrypted).toEqual(seed)
  })

  it('fails with wrong password', { timeout: 10_000 }, async () => {
    const seed = new Uint8Array(64)
    const password = 'correct-password'

    const encrypted = await encryptSeed(seed, password)
    await expect(decryptSeed(encrypted, 'wrong-password')).rejects.toThrow(
      DecryptionFailedError,
    )
  })

  it('rejects empty seed', async () => {
    await expect(encryptSeed(new Uint8Array(0), 'password')).rejects.toThrow(
      InvalidSeedError,
    )
  })

  it('rejects too-short encrypted data', async () => {
    await expect(
      decryptSeed(new Uint8Array([0x01, 0x02, 0x03]), 'password'),
    ).rejects.toThrow(DecryptionFailedError)
  })

  it(
    'produces different ciphertexts for same input (random salt/nonce)',
    async () => {
      const seed = new Uint8Array(64)
      const password = 'same-password'

      const enc1 = await encryptSeed(seed, password)
      const enc2 = await encryptSeed(seed, password)

      // Different due to random salt and nonce
      expect(enc1).not.toEqual(enc2)

      // Both should decrypt correctly
      const dec1 = await decryptSeed(enc1, password)
      const dec2 = await decryptSeed(enc2, password)
      expect(dec1).toEqual(seed)
      expect(dec2).toEqual(seed)
    },
    15_000,
  )

  it('produces correct output format (salt + nonce + ciphertext)', { timeout: 10_000 }, async () => {
    const seed = new Uint8Array(64)
    for (let i = 0; i < seed.length; i++) seed[i] = i * 3

    const encrypted = await encryptSeed(seed, 'format-test')

    // AES-GCM overhead = 16 bytes (auth tag)
    // Plaintext = seed(64) + checksum(4) = 68 bytes
    // Expected minimum: salt(16) + nonce(12) + plaintext(68) + tag(16) = 112
    const expectedMinLen = SALT_LEN + NONCE_LEN + seed.length + CHECKSUM_LEN + 16
    expect(encrypted.length).toBeGreaterThanOrEqual(expectedMinLen)

    // Salt (first 16 bytes) should not be all zeros
    const salt = encrypted.slice(0, SALT_LEN)
    const allZeroSalt = salt.every((b) => b === 0)
    expect(allZeroSalt).toBe(false)

    // Nonce (next 12 bytes) should not be all zeros
    const nonce = encrypted.slice(SALT_LEN, SALT_LEN + NONCE_LEN)
    const allZeroNonce = nonce.every((b) => b === 0)
    expect(allZeroNonce).toBe(false)
  })

  it('fails on corrupted ciphertext', { timeout: 10_000 }, async () => {
    const seed = new Uint8Array(64)
    for (let i = 0; i < seed.length; i++) seed[i] = i
    const password = 'correct-password'

    const encrypted = await encryptSeed(seed, password)
    const corrupted = new Uint8Array(encrypted)
    const ciphertextOffset = SALT_LEN + NONCE_LEN
    corrupted[ciphertextOffset + 5] ^= 0xff // bit-flip

    await expect(decryptSeed(corrupted, password)).rejects.toThrow(DecryptionFailedError)
  })

  it('round-trips with empty password', { timeout: 10_000 }, async () => {
    const seed = new Uint8Array(64)
    for (let i = 0; i < seed.length; i++) seed[i] = i + 100

    const encrypted = await encryptSeed(seed, '')
    const decrypted = await decryptSeed(encrypted, '')
    expect(decrypted).toEqual(seed)
  })

  it('round-trips with unicode password', { timeout: 10_000 }, async () => {
    const seed = new Uint8Array(64)
    for (let i = 0; i < seed.length; i++) seed[i] = i + 50
    const password = '\u4f60\u597d\u4e16\u754c\ud83d\udd12'

    const encrypted = await encryptSeed(seed, password)
    const decrypted = await decryptSeed(encrypted, password)
    expect(decrypted).toEqual(seed)
  })
})
