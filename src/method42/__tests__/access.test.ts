import { describe, it, expect } from 'vitest'
import { PrivateKey } from '@bsv/sdk'
import { Access, accessToString, freePrivateKey, effectivePrivateKey } from '../access.js'
import { ErrNilPrivateKey, ErrInvalidAccess } from '../errors.js'

describe('accessToString', () => {
  it('returns PRIVATE for Access.Private', () => {
    expect(accessToString(Access.Private)).toBe('PRIVATE')
  })

  it('returns FREE for Access.Free', () => {
    expect(accessToString(Access.Free)).toBe('FREE')
  })

  it('returns PAID for Access.Paid', () => {
    expect(accessToString(Access.Paid)).toBe('PAID')
  })

  it('returns UNKNOWN for invalid values', () => {
    expect(accessToString(99 as Access)).toBe('UNKNOWN')
  })
})

describe('freePrivateKey', () => {
  it('returns a PrivateKey with scalar value 1', () => {
    const key = freePrivateKey()
    expect(key).toBeInstanceOf(PrivateKey)
    // scalar 1 means toHex() should be 64 hex chars (32 bytes) with value 1
    expect(key.toHex()).toMatch(/^0{62}01$/)
  })

  it('returns a consistent key each time', () => {
    const k1 = freePrivateKey()
    const k2 = freePrivateKey()
    expect(k1.toHex()).toBe(k2.toHex())
  })

  it('can derive a public key', () => {
    const key = freePrivateKey()
    const pubKey = key.toPublicKey()
    expect(pubKey).toBeDefined()
  })
})

describe('effectivePrivateKey', () => {
  it('returns freePrivateKey for Access.Free regardless of input', () => {
    const result = effectivePrivateKey(Access.Free, null)
    expect(result.toHex()).toBe(freePrivateKey().toHex())
  })

  it('returns freePrivateKey for Access.Free even with a real key', () => {
    const realKey = PrivateKey.fromRandom()
    const result = effectivePrivateKey(Access.Free, realKey)
    expect(result.toHex()).toBe(freePrivateKey().toHex())
  })

  it('returns provided key for Access.Private', () => {
    const realKey = PrivateKey.fromRandom()
    const result = effectivePrivateKey(Access.Private, realKey)
    expect(result.toHex()).toBe(realKey.toHex())
  })

  it('returns provided key for Access.Paid', () => {
    const realKey = PrivateKey.fromRandom()
    const result = effectivePrivateKey(Access.Paid, realKey)
    expect(result.toHex()).toBe(realKey.toHex())
  })

  it('throws ErrNilPrivateKey for Access.Private with null key', () => {
    expect(() => effectivePrivateKey(Access.Private, null)).toThrow(ErrNilPrivateKey())
  })

  it('throws ErrNilPrivateKey for Access.Paid with null key', () => {
    expect(() => effectivePrivateKey(Access.Paid, null)).toThrow(ErrNilPrivateKey())
  })

  it('throws ErrInvalidAccess for unknown access mode', () => {
    expect(() => effectivePrivateKey(99 as Access, null)).toThrow(ErrInvalidAccess())
  })
})
