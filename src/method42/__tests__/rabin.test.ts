import { describe, it, expect } from 'vitest'
import {
  generateRabinKey,
  rabinSign,
  rabinVerify,
  serializeRabinSignature,
  deserializeRabinSignature,
  serializeRabinPubKey,
  deserializeRabinPubKey,
} from '../rabin.js'

describe('generateRabinKey', () => {
  it('generates a valid key pair with 512-bit primes', async () => {
    const key = await generateRabinKey(512)

    // p and q should be different
    expect(key.p).not.toBe(key.q)

    // n = p * q
    expect(key.n).toBe(key.p * key.q)

    // p ≡ 3 (mod 4) and q ≡ 3 (mod 4)
    expect(key.p % 4n).toBe(3n)
    expect(key.q % 4n).toBe(3n)
  })
}, 30_000) // Give generous timeout for key generation

describe('rabinSign / rabinVerify', () => {
  it('sign and verify a message', async () => {
    const key = await generateRabinKey(512)
    const message = new TextEncoder().encode('Hello, BitFS!')

    const { sig, pad } = rabinSign(key, message)

    expect(rabinVerify(key.n, message, sig, pad)).toBe(true)
  }, 30_000)

  it('verify rejects tampered message', async () => {
    const key = await generateRabinKey(512)
    const message = new TextEncoder().encode('original')
    const { sig, pad } = rabinSign(key, message)

    const tampered = new TextEncoder().encode('tampered')
    expect(rabinVerify(key.n, tampered, sig, pad)).toBe(false)
  }, 30_000)

  it('signs and verifies multiple messages', async () => {
    const key = await generateRabinKey(512)
    const messages = [
      new TextEncoder().encode('message 1'),
      new TextEncoder().encode('message 2'),
      new Uint8Array(0), // empty message
      new Uint8Array(1000).fill(0xab), // larger message
    ]

    for (const msg of messages) {
      const { sig, pad } = rabinSign(key, msg)
      expect(rabinVerify(key.n, msg, sig, pad)).toBe(true)
    }
  }, 30_000)

  it('verify rejects wrong signature', async () => {
    const key = await generateRabinKey(512)
    const message = new TextEncoder().encode('test')
    const { sig, pad } = rabinSign(key, message)

    // Use a different sig value
    const wrongSig = sig + 1n
    expect(rabinVerify(key.n, message, wrongSig, pad)).toBe(false)
  }, 30_000)
})

describe('Rabin serialization', () => {
  it('round-trips signature serialization', async () => {
    const key = await generateRabinKey(512)
    const message = new TextEncoder().encode('serialization test')
    const { sig, pad } = rabinSign(key, message)

    // Serialize
    const data = serializeRabinSignature(sig, pad)
    expect(data.length).toBeGreaterThan(0)

    // Deserialize
    const { sig: sig2, pad: pad2 } = deserializeRabinSignature(data)
    expect(sig2).toBe(sig)
    expect(Array.from(pad2)).toEqual(Array.from(pad))

    // Verify with deserialized values
    expect(rabinVerify(key.n, message, sig2, pad2)).toBe(true)
  }, 30_000)

  it('round-trips public key serialization', async () => {
    const key = await generateRabinKey(512)
    const data = serializeRabinPubKey(key.n)
    const n2 = deserializeRabinPubKey(data)
    expect(n2).toBe(key.n)
  }, 30_000)

  it('throws on too-short signature data', () => {
    expect(() => deserializeRabinSignature(new Uint8Array(4))).toThrow('too short')
  })

  it('throws on truncated S', () => {
    // Encode S length as 100 but only provide 4 bytes total
    const data = new Uint8Array(8)
    data[3] = 100 // sLen = 100
    expect(() => deserializeRabinSignature(data)).toThrow('S truncated')
  })

  it('throws on empty pubkey data', () => {
    expect(() => deserializeRabinPubKey(new Uint8Array(0))).toThrow('empty')
  })
})
