// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import { describe, it, expect } from 'vitest'

import { parseURI, isPubKeyHex, validateCompressedPubKey, bytesToHex } from '../uri.js'
import { AddressType, addressTypeString } from '../types.js'
import { InvalidURIError, InvalidPubKeyError } from '../errors.js'

// A valid compressed secp256k1 public key (33 bytes, prefix 02).
const testPubKeyHex =
  '02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2'

// ---------------------------------------------------------------------------
// parseURI - Paymail
// ---------------------------------------------------------------------------

describe('parseURI - Paymail', () => {
  const cases = [
    {
      name: 'basic paymail',
      uri: 'bitfs://alice@example.com/docs/paper.pdf',
      alias: 'alice',
      domain: 'example.com',
      path: '/docs/paper.pdf',
    },
    {
      name: 'paymail no path',
      uri: 'bitfs://bob@mail.example.com',
      alias: 'bob',
      domain: 'mail.example.com',
      path: '',
    },
    {
      name: 'paymail root path',
      uri: 'bitfs://user@domain.org/',
      alias: 'user',
      domain: 'domain.org',
      path: '/',
    },
    {
      name: 'paymail with subdomain',
      uri: 'bitfs://satoshi@paymail.bsv.com/hello',
      alias: 'satoshi',
      domain: 'paymail.bsv.com',
      path: '/hello',
    },
  ]

  for (const tc of cases) {
    it(tc.name, () => {
      const parsed = parseURI(tc.uri)
      expect(parsed.type).toBe(AddressType.Paymail)
      expect(parsed.alias).toBe(tc.alias)
      expect(parsed.domain).toBe(tc.domain)
      expect(parsed.path).toBe(tc.path)
      expect(parsed.rawURI).toBe(tc.uri)
      expect(parsed.pubKey).toBeNull()
    })
  }
})

// ---------------------------------------------------------------------------
// parseURI - DNSLink
// ---------------------------------------------------------------------------

describe('parseURI - DNSLink', () => {
  const cases = [
    {
      name: 'basic domain',
      uri: 'bitfs://example.com/docs/paper.pdf',
      domain: 'example.com',
      path: '/docs/paper.pdf',
    },
    {
      name: 'domain no path',
      uri: 'bitfs://example.com',
      domain: 'example.com',
      path: '',
    },
    {
      name: 'domain with subdomain',
      uri: 'bitfs://cdn.example.com/data',
      domain: 'cdn.example.com',
      path: '/data',
    },
  ]

  for (const tc of cases) {
    it(tc.name, () => {
      const parsed = parseURI(tc.uri)
      expect(parsed.type).toBe(AddressType.DNSLink)
      expect(parsed.domain).toBe(tc.domain)
      expect(parsed.path).toBe(tc.path)
      expect(parsed.alias).toBe('')
      expect(parsed.pubKey).toBeNull()
    })
  }
})

// ---------------------------------------------------------------------------
// parseURI - PubKey
// ---------------------------------------------------------------------------

describe('parseURI - PubKey', () => {
  const cases = [
    {
      name: '02 prefix pubkey with path',
      uri: `bitfs://${testPubKeyHex}/docs/paper.pdf`,
      path: '/docs/paper.pdf',
    },
    {
      name: '02 prefix pubkey no path',
      uri: `bitfs://${testPubKeyHex}`,
      path: '',
    },
    {
      name: '03 prefix pubkey',
      uri: `bitfs://03a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2/file.txt`,
      path: '/file.txt',
    },
  ]

  for (const tc of cases) {
    it(tc.name, () => {
      const parsed = parseURI(tc.uri)
      expect(parsed.type).toBe(AddressType.PubKey)
      expect(parsed.pubKey).not.toBeNull()
      expect(parsed.pubKey!.length).toBe(33)
      expect(parsed.path).toBe(tc.path)
      expect(parsed.alias).toBe('')
      expect(parsed.domain).toBe('')
    })
  }
})

// ---------------------------------------------------------------------------
// parseURI - Errors
// ---------------------------------------------------------------------------

describe('parseURI - errors', () => {
  const cases = [
    { name: 'empty string', uri: '' },
    { name: 'wrong scheme', uri: 'https://example.com' },
    { name: 'http scheme', uri: 'http://example.com' },
    { name: 'ipfs scheme', uri: 'ipfs://something' },
    { name: 'no authority', uri: 'bitfs://' },
    { name: 'empty alias', uri: 'bitfs://@example.com/path' },
    { name: 'empty domain after @', uri: 'bitfs://alice@/path' },
  ]

  for (const tc of cases) {
    it(tc.name, () => {
      expect(() => parseURI(tc.uri)).toThrow(InvalidURIError)
    })
  }
})

// ---------------------------------------------------------------------------
// parseURI - case sensitivity
// ---------------------------------------------------------------------------

describe('parseURI - case-sensitive scheme', () => {
  const cases = [
    { name: 'all caps', uri: 'BITFS://example.com' },
    { name: 'mixed case', uri: 'BitFs://example.com' },
    { name: 'uppercase B', uri: 'Bitfs://example.com' },
    { name: 'uppercase trailing', uri: 'bitFS://example.com' },
  ]

  for (const tc of cases) {
    it(tc.name, () => {
      expect(() => parseURI(tc.uri)).toThrow(InvalidURIError)
    })
  }
})

// ---------------------------------------------------------------------------
// parseURI - whitespace
// ---------------------------------------------------------------------------

describe('parseURI - whitespace', () => {
  const cases = [
    { name: 'leading space', uri: ' bitfs://example.com' },
    { name: 'leading tab', uri: '\tbitfs://example.com' },
    { name: 'leading newline', uri: '\nbitfs://example.com' },
  ]

  for (const tc of cases) {
    it(tc.name, () => {
      expect(() => parseURI(tc.uri)).toThrow(InvalidURIError)
    })
  }
})

// ---------------------------------------------------------------------------
// parseURI - paths with query and fragment
// ---------------------------------------------------------------------------

describe('parseURI - path with query and fragment', () => {
  const cases = [
    {
      name: 'path with query string',
      uri: 'bitfs://alice@example.com/docs/file.pdf?version=2',
      path: '/docs/file.pdf?version=2',
    },
    {
      name: 'path with fragment',
      uri: 'bitfs://alice@example.com/docs/file.pdf#page=5',
      path: '/docs/file.pdf#page=5',
    },
    {
      name: 'path with query and fragment',
      uri: 'bitfs://alice@example.com/docs/file.pdf?v=2#page=5',
      path: '/docs/file.pdf?v=2#page=5',
    },
    {
      name: 'DNSLink path with query',
      uri: 'bitfs://example.com/file.txt?download=true',
      path: '/file.txt?download=true',
    },
  ]

  for (const tc of cases) {
    it(tc.name, () => {
      const parsed = parseURI(tc.uri)
      expect(parsed.path).toBe(tc.path)
    })
  }
})

// ---------------------------------------------------------------------------
// parseURI - edge: short hex looks like DNSLink
// ---------------------------------------------------------------------------

describe('parseURI - pubkey vs DNSLink edge case', () => {
  it('64 hex chars (not 66) classified as DNSLink', () => {
    // 02 prefix + 31 bytes = 64 hex chars total, not 66
    const shortHex = '02' + 'ab'.repeat(31) // 64 chars
    const parsed = parseURI(`bitfs://${shortHex}/path`)
    expect(parsed.type).toBe(AddressType.DNSLink)
    expect(parsed.domain).toBe(shortHex)
    expect(parsed.path).toBe('/path')
    expect(parsed.pubKey).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// addressTypeString
// ---------------------------------------------------------------------------

describe('addressTypeString', () => {
  it('returns correct labels', () => {
    expect(addressTypeString(AddressType.Paymail)).toBe('Paymail')
    expect(addressTypeString(AddressType.DNSLink)).toBe('DNSLink')
    expect(addressTypeString(AddressType.PubKey)).toBe('PubKey')
    expect(addressTypeString(99 as AddressType)).toBe('Unknown')
  })
})

// ---------------------------------------------------------------------------
// isPubKeyHex
// ---------------------------------------------------------------------------

describe('isPubKeyHex', () => {
  const cases = [
    { name: 'valid 02', s: testPubKeyHex, want: true },
    { name: 'valid 03', s: '03' + 'ab'.repeat(32), want: true },
    { name: 'too short', s: '02abc', want: false },
    { name: 'too long', s: '02' + 'ab'.repeat(33), want: false },
    { name: 'wrong prefix', s: '04' + 'ab'.repeat(32), want: false },
    { name: 'not hex', s: '02' + 'zz'.repeat(32), want: false },
    { name: 'empty', s: '', want: false },
    { name: 'domain-like', s: 'example.com', want: false },
  ]

  for (const tc of cases) {
    it(tc.name, () => {
      expect(isPubKeyHex(tc.s)).toBe(tc.want)
    })
  }
})

// ---------------------------------------------------------------------------
// validateCompressedPubKey
// ---------------------------------------------------------------------------

describe('validateCompressedPubKey', () => {
  it('accepts valid 02 prefix', () => {
    const key = hexDecode(testPubKeyHex)
    expect(() => validateCompressedPubKey(key)).not.toThrow()
  })

  it('accepts valid 03 prefix', () => {
    const key = hexDecode('03' + 'ab'.repeat(32))
    expect(() => validateCompressedPubKey(key)).not.toThrow()
  })

  it('rejects too short', () => {
    expect(() => validateCompressedPubKey(new Uint8Array([0x02, 0x01, 0x02]))).toThrow(
      InvalidPubKeyError,
    )
  })

  it('rejects too long', () => {
    expect(() => validateCompressedPubKey(new Uint8Array(65))).toThrow(
      InvalidPubKeyError,
    )
  })

  it('rejects wrong prefix 04', () => {
    const key = new Uint8Array(33)
    key[0] = 0x04
    expect(() => validateCompressedPubKey(key)).toThrow(InvalidPubKeyError)
  })

  it('rejects wrong prefix 00', () => {
    const key = new Uint8Array(33)
    key[0] = 0x00
    expect(() => validateCompressedPubKey(key)).toThrow(InvalidPubKeyError)
  })

  it('rejects empty array', () => {
    expect(() => validateCompressedPubKey(new Uint8Array(0))).toThrow(
      InvalidPubKeyError,
    )
  })
})

// ---------------------------------------------------------------------------
// bytesToHex
// ---------------------------------------------------------------------------

describe('bytesToHex', () => {
  it('encodes bytes to lowercase hex', () => {
    expect(bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe('deadbeef')
  })

  it('handles empty array', () => {
    expect(bytesToHex(new Uint8Array(0))).toBe('')
  })

  it('zero-pads single-digit bytes', () => {
    expect(bytesToHex(new Uint8Array([0x01, 0x0a]))).toBe('010a')
  })
})

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function hexDecode(hex: string): Uint8Array {
  const len = hex.length / 2
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}
