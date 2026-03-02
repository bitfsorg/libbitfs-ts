import { describe, it, expect } from 'vitest'
import { PrivateKey } from '@bsv/sdk'
import { Access } from '../access.js'
import {
  encrypt,
  decrypt,
  reEncrypt,
  encryptMetadata,
  decryptMetadata,
  NONCE_LEN,
  GCM_TAG_LEN,
  MIN_CIPHERTEXT_LEN,
  MIN_ENC_PAYLOAD_LEN,
} from '../encrypt.js'
import { computeKeyHash, METADATA_SALT_LEN } from '../kdf.js'
import {
  ErrNilPublicKey,
  ErrNilPrivateKey,
  ErrInvalidCiphertext,
  ErrDecryptionFailed,
  ErrKeyHashMismatch,
} from '../errors.js'

function generateKeyPair() {
  const priv = PrivateKey.fromRandom()
  const pub = priv.toPublicKey()
  return { priv, pub }
}

describe('encrypt/decrypt round-trip', () => {
  it('encrypts and decrypts with Access.Private', async () => {
    const { priv, pub } = generateKeyPair()
    const plaintext = new TextEncoder().encode('hello world')

    const enc = await encrypt(plaintext, priv, pub, Access.Private)
    expect(enc.ciphertext.length).toBeGreaterThanOrEqual(MIN_CIPHERTEXT_LEN)
    expect(enc.keyHash).toHaveLength(32)

    const dec = await decrypt(enc.ciphertext, priv, pub, enc.keyHash, Access.Private)
    expect(new TextDecoder().decode(dec.plaintext)).toBe('hello world')
    expect(Array.from(dec.keyHash)).toEqual(Array.from(enc.keyHash))
  })

  it('encrypts and decrypts with Access.Free', async () => {
    const { priv, pub } = generateKeyPair()
    const plaintext = new TextEncoder().encode('free content')

    const enc = await encrypt(plaintext, null, pub, Access.Free)
    const dec = await decrypt(enc.ciphertext, null, pub, enc.keyHash, Access.Free)
    expect(new TextDecoder().decode(dec.plaintext)).toBe('free content')
  })

  it('encrypts and decrypts with Access.Paid', async () => {
    const { priv, pub } = generateKeyPair()
    const plaintext = new TextEncoder().encode('paid content')

    const enc = await encrypt(plaintext, priv, pub, Access.Paid)
    const dec = await decrypt(enc.ciphertext, priv, pub, enc.keyHash, Access.Paid)
    expect(new TextDecoder().decode(dec.plaintext)).toBe('paid content')
  })

  it('encrypts and decrypts empty plaintext', async () => {
    const { priv, pub } = generateKeyPair()
    const plaintext = new Uint8Array(0)

    const enc = await encrypt(plaintext, priv, pub, Access.Private)
    const dec = await decrypt(enc.ciphertext, priv, pub, enc.keyHash, Access.Private)
    expect(dec.plaintext).toHaveLength(0)
  })

  it('encrypts and decrypts large plaintext', async () => {
    const { priv, pub } = generateKeyPair()
    const plaintext = new Uint8Array(1024 * 100)
    // Fill in 65536-byte chunks (crypto.getRandomValues limit)
    for (let offset = 0; offset < plaintext.length; offset += 65536) {
      const len = Math.min(65536, plaintext.length - offset)
      crypto.getRandomValues(plaintext.subarray(offset, offset + len))
    }

    const enc = await encrypt(plaintext, priv, pub, Access.Private)
    const dec = await decrypt(enc.ciphertext, priv, pub, enc.keyHash, Access.Private)
    expect(Array.from(dec.plaintext)).toEqual(Array.from(plaintext))
  })
})

describe('encrypt ciphertext format', () => {
  it('ciphertext includes nonce prefix', async () => {
    const { priv, pub } = generateKeyPair()
    const plaintext = new TextEncoder().encode('format test')
    const enc = await encrypt(plaintext, priv, pub, Access.Private)

    // ciphertext = nonce(12B) + encrypted_data + tag(16B)
    expect(enc.ciphertext.length).toBe(NONCE_LEN + plaintext.length + GCM_TAG_LEN)
  })

  it('keyHash matches computeKeyHash', async () => {
    const { priv, pub } = generateKeyPair()
    const plaintext = new TextEncoder().encode('hash test')

    const enc = await encrypt(plaintext, priv, pub, Access.Private)
    const expected = computeKeyHash(plaintext)
    expect(Array.from(enc.keyHash)).toEqual(Array.from(expected))
  })

  it('different encryptions produce different ciphertexts (random nonce)', async () => {
    const { priv, pub } = generateKeyPair()
    const plaintext = new TextEncoder().encode('nonce test')

    const enc1 = await encrypt(plaintext, priv, pub, Access.Private)
    const enc2 = await encrypt(plaintext, priv, pub, Access.Private)

    // Same keyHash but different ciphertext due to random nonce
    expect(Array.from(enc1.keyHash)).toEqual(Array.from(enc2.keyHash))
    expect(Array.from(enc1.ciphertext)).not.toEqual(Array.from(enc2.ciphertext))
  })
})

describe('decrypt error cases', () => {
  it('throws on null public key', async () => {
    await expect(encrypt(new Uint8Array([1]), null, null, Access.Free))
      .rejects.toThrow(ErrNilPublicKey)
  })

  it('throws on wrong key hash', async () => {
    const { priv, pub } = generateKeyPair()
    const enc = await encrypt(new TextEncoder().encode('test'), priv, pub, Access.Private)

    const wrongHash = new Uint8Array(32).fill(0xff)
    await expect(decrypt(enc.ciphertext, priv, pub, wrongHash, Access.Private))
      .rejects.toThrow()
  })

  it('throws on too-short ciphertext', async () => {
    const { priv, pub } = generateKeyPair()
    const keyHash = new Uint8Array(32)
    await expect(decrypt(new Uint8Array(10), priv, pub, keyHash, Access.Private))
      .rejects.toThrow(ErrInvalidCiphertext)
  })

  it('throws on tampered ciphertext', async () => {
    const { priv, pub } = generateKeyPair()
    const enc = await encrypt(new TextEncoder().encode('tamper test'), priv, pub, Access.Private)

    // Tamper with the ciphertext (after the nonce)
    const tampered = new Uint8Array(enc.ciphertext)
    tampered[NONCE_LEN] ^= 0xff

    await expect(decrypt(tampered, priv, pub, enc.keyHash, Access.Private))
      .rejects.toThrow(ErrDecryptionFailed)
  })

  it('throws on wrong access mode', async () => {
    const { priv, pub } = generateKeyPair()
    const enc = await encrypt(new TextEncoder().encode('mode test'), priv, pub, Access.Private)

    // Decrypting Private content with Free key should fail
    await expect(decrypt(enc.ciphertext, null, pub, enc.keyHash, Access.Free))
      .rejects.toThrow()
  })
})

describe('reEncrypt', () => {
  it('re-encrypts from FREE to PRIVATE', async () => {
    const { priv, pub } = generateKeyPair()
    const plaintext = new TextEncoder().encode('re-encrypt test')

    // Encrypt as FREE
    const freeEnc = await encrypt(plaintext, null, pub, Access.Free)

    // Re-encrypt as PRIVATE
    const privEnc = await reEncrypt(freeEnc.ciphertext, priv, pub, freeEnc.keyHash, Access.Free, Access.Private)

    // Decrypt as PRIVATE
    const dec = await decrypt(privEnc.ciphertext, priv, pub, privEnc.keyHash, Access.Private)
    expect(new TextDecoder().decode(dec.plaintext)).toBe('re-encrypt test')
  })

  it('re-encrypts from PRIVATE to FREE', async () => {
    const { priv, pub } = generateKeyPair()
    const plaintext = new TextEncoder().encode('unlock test')

    const privEnc = await encrypt(plaintext, priv, pub, Access.Private)
    const freeEnc = await reEncrypt(privEnc.ciphertext, priv, pub, privEnc.keyHash, Access.Private, Access.Free)
    const dec = await decrypt(freeEnc.ciphertext, null, pub, freeEnc.keyHash, Access.Free)
    expect(new TextDecoder().decode(dec.plaintext)).toBe('unlock test')
  })
})

describe('encryptMetadata/decryptMetadata', () => {
  it('round-trips TLV payload', async () => {
    const { priv, pub } = generateKeyPair()
    const tlv = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05])

    const encPayload = await encryptMetadata(tlv, priv, pub)
    expect(encPayload.length).toBeGreaterThanOrEqual(MIN_ENC_PAYLOAD_LEN)

    const decrypted = await decryptMetadata(encPayload, priv, pub)
    expect(Array.from(decrypted)).toEqual(Array.from(tlv))
  })

  it('encPayload starts with 16-byte salt', async () => {
    const { priv, pub } = generateKeyPair()
    const tlv = new Uint8Array([0xff])

    const encPayload = await encryptMetadata(tlv, priv, pub)
    // salt(16B) + nonce(12B) + ciphertext(1B) + tag(16B)
    expect(encPayload.length).toBe(METADATA_SALT_LEN + NONCE_LEN + 1 + GCM_TAG_LEN)
  })

  it('throws on null private key', async () => {
    const pub = PrivateKey.fromRandom().toPublicKey()
    await expect(encryptMetadata(new Uint8Array([1]), null, pub))
      .rejects.toThrow(ErrNilPrivateKey)
  })

  it('throws on null public key', async () => {
    const priv = PrivateKey.fromRandom()
    await expect(encryptMetadata(new Uint8Array([1]), priv, null))
      .rejects.toThrow(ErrNilPublicKey)
  })

  it('throws on too-short encPayload', async () => {
    const { priv, pub } = generateKeyPair()
    await expect(decryptMetadata(new Uint8Array(10), priv, pub))
      .rejects.toThrow(ErrInvalidCiphertext)
  })

  it('round-trips empty TLV payload', async () => {
    const { priv, pub } = generateKeyPair()
    const tlv = new Uint8Array(0)

    const encPayload = await encryptMetadata(tlv, priv, pub)
    const decrypted = await decryptMetadata(encPayload, priv, pub)
    expect(decrypted).toHaveLength(0)
  })
})
