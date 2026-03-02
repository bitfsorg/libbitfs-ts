import { describe, it, expect } from 'vitest'
import { PrivateKey, Hash } from '@bsv/sdk'
import { ecdh } from '../ecdh.js'
import {
  computeKeyHash,
  deriveAESKey,
  deriveMetadataKey,
  deriveMetadataKeyWithSalt,
  deriveBuyerMask,
  deriveBuyerMaskWithNonce,
  HKDF_INFO,
  AES_KEY_LEN,
  METADATA_SALT_LEN,
  HASH_SIZE,
} from '../kdf.js'
import { ErrNilPrivateKey, ErrNilPublicKey } from '../errors.js'

describe('computeKeyHash', () => {
  it('returns 32 bytes', () => {
    const hash = computeKeyHash(new Uint8Array([1, 2, 3]))
    expect(hash).toHaveLength(32)
  })

  it('computes double-SHA256', () => {
    const data = new Uint8Array([104, 101, 108, 108, 111]) // "hello"
    const hash = computeKeyHash(data)

    // Manual double SHA256
    const first = Hash.sha256(Array.from(data))
    const second = Hash.sha256(first)

    expect(Array.from(hash)).toEqual(second)
  })

  it('is deterministic', () => {
    const data = new Uint8Array([1, 2, 3, 4])
    expect(Array.from(computeKeyHash(data))).toEqual(Array.from(computeKeyHash(data)))
  })

  it('produces different hashes for different inputs', () => {
    const h1 = computeKeyHash(new Uint8Array([1]))
    const h2 = computeKeyHash(new Uint8Array([2]))
    expect(Array.from(h1)).not.toEqual(Array.from(h2))
  })

  it('handles empty input', () => {
    const hash = computeKeyHash(new Uint8Array(0))
    expect(hash).toHaveLength(32)
  })
})

describe('ECDH', () => {
  it('returns 32-byte x-coordinate', () => {
    const priv = PrivateKey.fromRandom()
    const pub = priv.toPublicKey()
    const shared = ecdh(priv, pub)
    expect(shared).toHaveLength(32)
  })

  it('throws on null private key', () => {
    const priv = PrivateKey.fromRandom()
    expect(() => ecdh(null, priv.toPublicKey())).toThrow(ErrNilPrivateKey())
  })

  it('throws on null public key', () => {
    const priv = PrivateKey.fromRandom()
    expect(() => ecdh(priv, null)).toThrow(ErrNilPublicKey())
  })

  it('is deterministic', () => {
    const priv = PrivateKey.fromRandom()
    const pub = priv.toPublicKey()
    const s1 = ecdh(priv, pub)
    const s2 = ecdh(priv, pub)
    expect(Array.from(s1)).toEqual(Array.from(s2))
  })

  it('produces different results for different keys', () => {
    const priv1 = PrivateKey.fromRandom()
    const priv2 = PrivateKey.fromRandom()
    const s1 = ecdh(priv1, priv1.toPublicKey())
    const s2 = ecdh(priv2, priv2.toPublicKey())
    expect(Array.from(s1)).not.toEqual(Array.from(s2))
  })

  it('satisfies ECDH symmetry: ECDH(a,B) == ECDH(b,A)', () => {
    const privA = PrivateKey.fromRandom()
    const privB = PrivateKey.fromRandom()
    const pubA = privA.toPublicKey()
    const pubB = privB.toPublicKey()

    const s1 = ecdh(privA, pubB) // a * B
    const s2 = ecdh(privB, pubA) // b * A

    expect(Array.from(s1)).toEqual(Array.from(s2))
  })
})

describe('deriveAESKey', () => {
  it('returns 32-byte key', () => {
    const sharedX = new Uint8Array(32).fill(1)
    const keyHash = computeKeyHash(new Uint8Array([1, 2, 3]))
    const key = deriveAESKey(sharedX, keyHash)
    expect(key).toHaveLength(AES_KEY_LEN)
  })

  it('is deterministic', () => {
    const sharedX = new Uint8Array(32).fill(42)
    const keyHash = computeKeyHash(new Uint8Array([5, 6, 7]))
    const k1 = deriveAESKey(sharedX, keyHash)
    const k2 = deriveAESKey(sharedX, keyHash)
    expect(Array.from(k1)).toEqual(Array.from(k2))
  })

  it('throws on empty shared secret', () => {
    const keyHash = new Uint8Array(32)
    expect(() => deriveAESKey(new Uint8Array(0), keyHash)).toThrow('shared secret is empty')
  })

  it('throws on wrong keyHash length', () => {
    const sharedX = new Uint8Array(32)
    expect(() => deriveAESKey(sharedX, new Uint8Array(16))).toThrow('key hash must be 32 bytes')
  })

  it('different inputs produce different keys', () => {
    const sharedX = new Uint8Array(32).fill(1)
    const kh1 = computeKeyHash(new Uint8Array([1]))
    const kh2 = computeKeyHash(new Uint8Array([2]))
    const k1 = deriveAESKey(sharedX, kh1)
    const k2 = deriveAESKey(sharedX, kh2)
    expect(Array.from(k1)).not.toEqual(Array.from(k2))
  })
})

describe('deriveMetadataKey', () => {
  it('returns key of 32 bytes and salt of 16 bytes', () => {
    const sharedX = new Uint8Array(32).fill(1)
    const { key, salt } = deriveMetadataKey(sharedX)
    expect(key).toHaveLength(AES_KEY_LEN)
    expect(salt).toHaveLength(METADATA_SALT_LEN)
  })

  it('produces random salt each time', () => {
    const sharedX = new Uint8Array(32).fill(1)
    const r1 = deriveMetadataKey(sharedX)
    const r2 = deriveMetadataKey(sharedX)
    // Salts should differ (random)
    expect(Array.from(r1.salt)).not.toEqual(Array.from(r2.salt))
  })
})

describe('deriveMetadataKeyWithSalt', () => {
  it('returns 32-byte key', () => {
    const sharedX = new Uint8Array(32).fill(1)
    const salt = new Uint8Array(METADATA_SALT_LEN).fill(0xab)
    const key = deriveMetadataKeyWithSalt(sharedX, salt)
    expect(key).toHaveLength(AES_KEY_LEN)
  })

  it('is deterministic for same inputs', () => {
    const sharedX = new Uint8Array(32).fill(7)
    const salt = new Uint8Array(METADATA_SALT_LEN).fill(0xcd)
    const k1 = deriveMetadataKeyWithSalt(sharedX, salt)
    const k2 = deriveMetadataKeyWithSalt(sharedX, salt)
    expect(Array.from(k1)).toEqual(Array.from(k2))
  })

  it('round-trips with deriveMetadataKey', () => {
    const sharedX = new Uint8Array(32).fill(3)
    const { key, salt } = deriveMetadataKey(sharedX)
    const key2 = deriveMetadataKeyWithSalt(sharedX, salt)
    expect(Array.from(key)).toEqual(Array.from(key2))
  })

  it('throws on empty shared secret', () => {
    expect(() => deriveMetadataKeyWithSalt(new Uint8Array(0), new Uint8Array(16))).toThrow('shared secret is empty')
  })

  it('throws on wrong salt length', () => {
    expect(() => deriveMetadataKeyWithSalt(new Uint8Array(32), new Uint8Array(8))).toThrow('metadata salt must be')
  })
})

describe('deriveBuyerMask', () => {
  it('returns 32-byte mask', () => {
    const sharedX = new Uint8Array(32).fill(1)
    const keyHash = new Uint8Array(32).fill(2)
    const mask = deriveBuyerMask(sharedX, keyHash)
    expect(mask).toHaveLength(AES_KEY_LEN)
  })

  it('is deterministic', () => {
    const sharedX = new Uint8Array(32).fill(5)
    const keyHash = new Uint8Array(32).fill(6)
    const m1 = deriveBuyerMask(sharedX, keyHash)
    const m2 = deriveBuyerMask(sharedX, keyHash)
    expect(Array.from(m1)).toEqual(Array.from(m2))
  })

  it('equals deriveBuyerMaskWithNonce(null)', () => {
    const sharedX = new Uint8Array(32).fill(10)
    const keyHash = new Uint8Array(32).fill(20)
    const m1 = deriveBuyerMask(sharedX, keyHash)
    const m2 = deriveBuyerMaskWithNonce(sharedX, keyHash, null)
    expect(Array.from(m1)).toEqual(Array.from(m2))
  })
})

describe('deriveBuyerMaskWithNonce', () => {
  it('produces different mask with nonce', () => {
    const sharedX = new Uint8Array(32).fill(1)
    const keyHash = new Uint8Array(32).fill(2)
    const nonce = new Uint8Array([1, 2, 3, 4])
    const m1 = deriveBuyerMask(sharedX, keyHash)
    const m2 = deriveBuyerMaskWithNonce(sharedX, keyHash, nonce)
    expect(Array.from(m1)).not.toEqual(Array.from(m2))
  })

  it('different nonces produce different masks', () => {
    const sharedX = new Uint8Array(32).fill(1)
    const keyHash = new Uint8Array(32).fill(2)
    const n1 = new Uint8Array([1, 2, 3, 4])
    const n2 = new Uint8Array([5, 6, 7, 8])
    const m1 = deriveBuyerMaskWithNonce(sharedX, keyHash, n1)
    const m2 = deriveBuyerMaskWithNonce(sharedX, keyHash, n2)
    expect(Array.from(m1)).not.toEqual(Array.from(m2))
  })

  it('throws on empty shared secret', () => {
    expect(() => deriveBuyerMaskWithNonce(new Uint8Array(0), new Uint8Array(32), null)).toThrow('shared secret is empty')
  })

  it('throws on wrong keyHash length', () => {
    expect(() => deriveBuyerMaskWithNonce(new Uint8Array(32), new Uint8Array(16), null)).toThrow('key hash must be 32 bytes')
  })
})
