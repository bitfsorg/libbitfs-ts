import { describe, it, expect } from 'vitest'
import { PrivateKey, Hash } from '@bsv/sdk'
import { Access } from '../access.js'
import { encrypt } from '../encrypt.js'
import {
  computeCapsule,
  computeCapsuleWithNonce,
  computeCapsuleHash,
  decryptWithCapsule,
  decryptWithCapsuleNonce,
} from '../capsule.js'
import { computeKeyHash, AES_KEY_LEN } from '../kdf.js'
import { ErrNilPrivateKey, ErrNilPublicKey, ErrKeyHashMismatch } from '../errors.js'

function generateKeyPair() {
  const priv = PrivateKey.fromRandom()
  const pub = priv.toPublicKey()
  return { priv, pub }
}

describe('computeCapsule', () => {
  it('returns 32-byte capsule', () => {
    const node = generateKeyPair()
    const buyer = generateKeyPair()
    const keyHash = computeKeyHash(new Uint8Array([1, 2, 3]))

    const capsule = computeCapsule(node.priv, node.pub, buyer.pub, keyHash)
    expect(capsule).toHaveLength(AES_KEY_LEN)
  })

  it('is deterministic', () => {
    const node = generateKeyPair()
    const buyer = generateKeyPair()
    const keyHash = computeKeyHash(new Uint8Array([1, 2, 3]))

    const c1 = computeCapsule(node.priv, node.pub, buyer.pub, keyHash)
    const c2 = computeCapsule(node.priv, node.pub, buyer.pub, keyHash)
    expect(Array.from(c1)).toEqual(Array.from(c2))
  })

  it('equals computeCapsuleWithNonce(null)', () => {
    const node = generateKeyPair()
    const buyer = generateKeyPair()
    const keyHash = computeKeyHash(new Uint8Array([5, 6, 7]))

    const c1 = computeCapsule(node.priv, node.pub, buyer.pub, keyHash)
    const c2 = computeCapsuleWithNonce(node.priv, node.pub, buyer.pub, keyHash, null)
    expect(Array.from(c1)).toEqual(Array.from(c2))
  })

  it('throws on wrong keyHash length', () => {
    const node = generateKeyPair()
    const buyer = generateKeyPair()
    expect(() => computeCapsule(node.priv, node.pub, buyer.pub, new Uint8Array(16)))
      .toThrow('keyHash must be 32 bytes')
  })
})

describe('computeCapsuleWithNonce', () => {
  it('produces different capsules with different nonces', () => {
    const node = generateKeyPair()
    const buyer = generateKeyPair()
    const keyHash = computeKeyHash(new Uint8Array([1, 2, 3]))

    const c1 = computeCapsuleWithNonce(node.priv, node.pub, buyer.pub, keyHash, new Uint8Array([1]))
    const c2 = computeCapsuleWithNonce(node.priv, node.pub, buyer.pub, keyHash, new Uint8Array([2]))
    expect(Array.from(c1)).not.toEqual(Array.from(c2))
  })

  it('nonce capsule differs from no-nonce capsule', () => {
    const node = generateKeyPair()
    const buyer = generateKeyPair()
    const keyHash = computeKeyHash(new Uint8Array([1, 2, 3]))

    const c1 = computeCapsule(node.priv, node.pub, buyer.pub, keyHash)
    const c2 = computeCapsuleWithNonce(node.priv, node.pub, buyer.pub, keyHash, new Uint8Array([0xab, 0xcd]))
    expect(Array.from(c1)).not.toEqual(Array.from(c2))
  })
})

describe('computeCapsuleHash', () => {
  it('returns 32-byte hash', () => {
    const fileTxID = new Uint8Array(32).fill(0xaa)
    const capsule = new Uint8Array(32).fill(0xbb)
    const hash = computeCapsuleHash(fileTxID, capsule)
    expect(hash).not.toBeNull()
    expect(hash!).toHaveLength(32)
  })

  it('returns null for non-32-byte fileTxID', () => {
    expect(computeCapsuleHash(new Uint8Array(16), new Uint8Array(32))).toBeNull()
  })

  it('is deterministic', () => {
    const fileTxID = new Uint8Array(32).fill(0x11)
    const capsule = new Uint8Array(32).fill(0x22)
    const h1 = computeCapsuleHash(fileTxID, capsule)!
    const h2 = computeCapsuleHash(fileTxID, capsule)!
    expect(Array.from(h1)).toEqual(Array.from(h2))
  })

  it('different inputs produce different hashes', () => {
    const fileTxID = new Uint8Array(32).fill(0x11)
    const cap1 = new Uint8Array(32).fill(0x22)
    const cap2 = new Uint8Array(32).fill(0x33)
    const h1 = computeCapsuleHash(fileTxID, cap1)!
    const h2 = computeCapsuleHash(fileTxID, cap2)!
    expect(Array.from(h1)).not.toEqual(Array.from(h2))
  })
})

describe('full buyer flow: encrypt PAID -> computeCapsule -> decryptWithCapsule', () => {
  it('buyer can decrypt with capsule', async () => {
    const node = generateKeyPair()
    const buyer = generateKeyPair()
    const plaintext = new TextEncoder().encode('paid content for buyer')

    // 1. Node owner encrypts as PAID
    const enc = await encrypt(plaintext, node.priv, node.pub, Access.Paid)

    // 2. Node owner computes capsule for this buyer
    const capsule = computeCapsule(node.priv, node.pub, buyer.pub, enc.keyHash)

    // 3. Buyer decrypts using capsule
    const dec = await decryptWithCapsule(enc.ciphertext, capsule, enc.keyHash, buyer.priv, node.pub)
    expect(new TextDecoder().decode(dec.plaintext)).toBe('paid content for buyer')
    expect(Array.from(dec.keyHash)).toEqual(Array.from(enc.keyHash))
  })

  it('buyer can decrypt with nonce capsule', async () => {
    const node = generateKeyPair()
    const buyer = generateKeyPair()
    const plaintext = new TextEncoder().encode('nonce paid content')
    const nonce = new Uint8Array([0xde, 0xad, 0xbe, 0xef])

    const enc = await encrypt(plaintext, node.priv, node.pub, Access.Paid)
    const capsule = computeCapsuleWithNonce(node.priv, node.pub, buyer.pub, enc.keyHash, nonce)
    const dec = await decryptWithCapsuleNonce(enc.ciphertext, capsule, enc.keyHash, buyer.priv, node.pub, nonce)
    expect(new TextDecoder().decode(dec.plaintext)).toBe('nonce paid content')
  })

  it('wrong buyer cannot decrypt', async () => {
    const node = generateKeyPair()
    const buyer = generateKeyPair()
    const wrongBuyer = generateKeyPair()
    const plaintext = new TextEncoder().encode('secret')

    const enc = await encrypt(plaintext, node.priv, node.pub, Access.Paid)
    const capsule = computeCapsule(node.priv, node.pub, buyer.pub, enc.keyHash)

    // Wrong buyer trying to use the capsule
    await expect(
      decryptWithCapsule(enc.ciphertext, capsule, enc.keyHash, wrongBuyer.priv, node.pub)
    ).rejects.toThrow()
  })

  it('wrong nonce fails decryption', async () => {
    const node = generateKeyPair()
    const buyer = generateKeyPair()
    const plaintext = new TextEncoder().encode('nonce test')
    const nonce = new Uint8Array([1, 2, 3, 4])
    const wrongNonce = new Uint8Array([5, 6, 7, 8])

    const enc = await encrypt(plaintext, node.priv, node.pub, Access.Paid)
    const capsule = computeCapsuleWithNonce(node.priv, node.pub, buyer.pub, enc.keyHash, nonce)

    await expect(
      decryptWithCapsuleNonce(enc.ciphertext, capsule, enc.keyHash, buyer.priv, node.pub, wrongNonce)
    ).rejects.toThrow()
  })
})

describe('decryptWithCapsule error cases', () => {
  it('throws on null buyer private key', async () => {
    await expect(
      decryptWithCapsule(new Uint8Array(28), new Uint8Array(32), new Uint8Array(32), null, PrivateKey.fromRandom().toPublicKey())
    ).rejects.toThrow(ErrNilPrivateKey())
  })

  it('throws on null node public key', async () => {
    await expect(
      decryptWithCapsule(new Uint8Array(28), new Uint8Array(32), new Uint8Array(32), PrivateKey.fromRandom(), null)
    ).rejects.toThrow(ErrNilPublicKey())
  })

  it('throws on empty capsule', async () => {
    const buyer = generateKeyPair()
    const node = generateKeyPair()
    await expect(
      decryptWithCapsule(new Uint8Array(28), new Uint8Array(0), new Uint8Array(32), buyer.priv, node.pub)
    ).rejects.toThrow('capsule is empty')
  })

  it('throws on wrong capsule size', async () => {
    const buyer = generateKeyPair()
    const node = generateKeyPair()
    await expect(
      decryptWithCapsule(new Uint8Array(28), new Uint8Array(16), new Uint8Array(32), buyer.priv, node.pub)
    ).rejects.toThrow('capsule must be')
  })
})
