import { describe, it, expect } from 'vitest'
import { calculatePrice, newInvoice, isExpired } from '../invoice.js'
import {
  parsePaymentHeaders,
  paymentHeadersFromInvoice,
  paymentHeadersToHeaders,
  HEADER_PRICE,
  HEADER_PRICE_PER_KB,
  HEADER_FILE_SIZE,
  HEADER_INVOICE_ID,
  HEADER_EXPIRY,
} from '../headers.js'
import { CAPSULE_HASH_LEN } from '../types.js'

// ---------------------------------------------------------------------------
// calculatePrice tests
// ---------------------------------------------------------------------------

describe('calculatePrice', () => {
  it('returns 0 for zero price', () => {
    expect(calculatePrice(0n, 1024n)).toBe(0n)
  })

  it('returns 0 for zero size', () => {
    expect(calculatePrice(50n, 0n)).toBe(0n)
  })

  it('returns 0 for both zero', () => {
    expect(calculatePrice(0n, 0n)).toBe(0n)
  })

  it('exact 1KB', () => {
    expect(calculatePrice(50n, 1024n)).toBe(50n)
  })

  it('exact 2KB', () => {
    expect(calculatePrice(50n, 2048n)).toBe(100n)
  })

  it('partial KB rounds up', () => {
    // ceil(50 * 1025 / 1024) = ceil(51250/1024) = ceil(50.048...) = 51
    expect(calculatePrice(50n, 1025n)).toBe(51n)
  })

  it('1 byte', () => {
    // ceil(50 * 1 / 1024) = ceil(0.048...) = 1
    expect(calculatePrice(50n, 1n)).toBe(1n)
  })

  it('512 bytes', () => {
    // ceil(100 * 512 / 1024) = ceil(50) = 50
    expect(calculatePrice(100n, 512n)).toBe(50n)
  })

  it('ceil(500 * 2048 / 1024) = 1000', () => {
    expect(calculatePrice(500n, 2048n)).toBe(1000n)
  })

  it('large file: 1MB at 10 sat/KB', () => {
    // 10 * 1048576 / 1024 = 10240
    expect(calculatePrice(10n, 1048576n)).toBe(10240n)
  })

  it('small price large file', () => {
    expect(calculatePrice(1n, 10240n)).toBe(10n)
  })

  it('large but safe values', () => {
    const price = calculatePrice(1_000_000n, 18_000_000_000_000n)
    const expected = (1_000_000n * 18_000_000_000_000n + 1023n) / 1024n
    expect(price).toBe(expected)
  })

  it('handles very large products (bigint has no overflow)', () => {
    // Unlike Go, bigint has no overflow concern.
    const price = calculatePrice(1n << 32n, 1n << 33n)
    const expected = ((1n << 32n) * (1n << 33n) + 1023n) / 1024n
    expect(price).toBe(expected)
  })
})

// ---------------------------------------------------------------------------
// Invoice creation tests
// ---------------------------------------------------------------------------

describe('newInvoice', () => {
  const capsuleHash = new Uint8Array(CAPSULE_HASH_LEN)
  capsuleHash[0] = 0xab

  it('creates invoice with correct fields', () => {
    const inv = newInvoice(50n, 2048n, '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', capsuleHash, 3600)

    expect(inv.id).toHaveLength(32) // 16 bytes hex-encoded = 32 chars
    expect(inv.price).toBe(100n) // 50 * 2048 / 1024 = 100
    expect(inv.pricePerKB).toBe(50n)
    expect(inv.fileSize).toBe(2048n)
    expect(inv.paymentAddr).toBe('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
    expect(inv.capsuleHash).toEqual(capsuleHash)

    const now = Math.floor(Date.now() / 1000)
    expect(inv.expiry).toBeGreaterThan(now)
    expect(inv.expiry).toBeLessThanOrEqual(now + 3601)
  })

  it('generates unique IDs', () => {
    const inv1 = newInvoice(10n, 1024n, 'addr1', capsuleHash, 60)
    const inv2 = newInvoice(10n, 1024n, 'addr1', capsuleHash, 60)
    expect(inv1.id).not.toBe(inv2.id)
  })

  it('throws on invalid capsule hash length', () => {
    expect(() =>
      newInvoice(10n, 1024n, 'addr', new Uint8Array(16), 60),
    ).toThrow('capsule hash must be 32 bytes')
  })

  it('throws on empty payment address', () => {
    expect(() =>
      newInvoice(10n, 1024n, '', capsuleHash, 60),
    ).toThrow('payment address is required')
  })

  it('throws on non-positive TTL', () => {
    expect(() =>
      newInvoice(10n, 1024n, 'addr', capsuleHash, 0),
    ).toThrow('ttlSeconds must be > 0')
  })
})

// ---------------------------------------------------------------------------
// isExpired tests
// ---------------------------------------------------------------------------

describe('isExpired', () => {
  it('returns true for expired invoice', () => {
    const capsuleHash = new Uint8Array(32)
    const inv = newInvoice(10n, 1024n, 'addr', capsuleHash, 1)
    // Manually set expiry to the past.
    inv.expiry = Math.floor(Date.now() / 1000) - 1
    expect(isExpired(inv)).toBe(true)
  })

  it('returns false for valid invoice', () => {
    const capsuleHash = new Uint8Array(32)
    const inv = newInvoice(10n, 1024n, 'addr', capsuleHash, 3600)
    expect(isExpired(inv)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Payment headers tests
// ---------------------------------------------------------------------------

describe('paymentHeadersFromInvoice', () => {
  it('converts invoice to payment headers', () => {
    const capsuleHash = new Uint8Array(32)
    const inv = newInvoice(50n, 10240n, 'addr', capsuleHash, 3600)

    const headers = paymentHeadersFromInvoice(inv)
    expect(headers.price).toBe(inv.price)
    expect(headers.pricePerKB).toBe(inv.pricePerKB)
    expect(headers.fileSize).toBe(inv.fileSize)
    expect(headers.invoiceID).toBe(inv.id)
    expect(headers.expiry).toBe(inv.expiry)
  })
})

describe('parsePaymentHeaders', () => {
  function makeHeaders(overrides: Record<string, string> = {}): Headers {
    const h = new Headers()
    h.set(HEADER_PRICE, '500')
    h.set(HEADER_PRICE_PER_KB, '50')
    h.set(HEADER_FILE_SIZE, '10240')
    h.set(HEADER_INVOICE_ID, 'abc123')
    h.set(HEADER_EXPIRY, '1708000000')
    for (const [k, v] of Object.entries(overrides)) {
      h.set(k, v)
    }
    return h
  }

  it('parses valid headers', () => {
    const parsed = parsePaymentHeaders(makeHeaders())
    expect(parsed.price).toBe(500n)
    expect(parsed.pricePerKB).toBe(50n)
    expect(parsed.fileSize).toBe(10240n)
    expect(parsed.invoiceID).toBe('abc123')
    expect(parsed.expiry).toBe(1708000000)
  })

  it('throws on missing price', () => {
    const h = makeHeaders()
    h.delete(HEADER_PRICE)
    expect(() => parsePaymentHeaders(h)).toThrow('X-Price header missing')
  })

  it('throws on missing price per KB', () => {
    const h = makeHeaders()
    h.delete(HEADER_PRICE_PER_KB)
    expect(() => parsePaymentHeaders(h)).toThrow('X-Price-Per-KB header missing')
  })

  it('throws on missing file size', () => {
    const h = makeHeaders()
    h.delete(HEADER_FILE_SIZE)
    expect(() => parsePaymentHeaders(h)).toThrow('X-File-Size header missing')
  })

  it('throws on missing invoice ID', () => {
    const h = makeHeaders()
    h.delete(HEADER_INVOICE_ID)
    expect(() => parsePaymentHeaders(h)).toThrow('X-Invoice-Id header missing')
  })

  it('throws on missing expiry', () => {
    const h = makeHeaders()
    h.delete(HEADER_EXPIRY)
    expect(() => parsePaymentHeaders(h)).toThrow('X-Expiry header missing')
  })

  it('throws on invalid price value', () => {
    expect(() => parsePaymentHeaders(makeHeaders({ [HEADER_PRICE]: 'not-a-number' }))).toThrow(
      'invalid X-Price value',
    )
  })

  it('throws on invalid expiry value', () => {
    expect(() => parsePaymentHeaders(makeHeaders({ [HEADER_EXPIRY]: 'tomorrow' }))).toThrow(
      'invalid X-Expiry value',
    )
  })
})

describe('payment headers round-trip', () => {
  it('serializes and deserializes correctly', () => {
    const capsuleHash = new Uint8Array(32)
    const inv = newInvoice(100n, 65536n, 'addr', capsuleHash, 3600)
    const ph = paymentHeadersFromInvoice(inv)
    const headers = paymentHeadersToHeaders(ph)
    const parsed = parsePaymentHeaders(headers)

    expect(parsed.price).toBe(ph.price)
    expect(parsed.pricePerKB).toBe(ph.pricePerKB)
    expect(parsed.fileSize).toBe(ph.fileSize)
    expect(parsed.invoiceID).toBe(ph.invoiceID)
    expect(parsed.expiry).toBe(ph.expiry)
  })
})
