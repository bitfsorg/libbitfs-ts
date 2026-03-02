// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import { describe, it, expect } from 'vitest'

import {
  discoverCapabilities,
  resolvePKI,
  resolvePaymentDestination,
} from '../discover.js'
import {
  PaymailDiscoveryError,
  PKIResolutionError,
  InvalidPubKeyError,
  AddressResolutionError,
} from '../errors.js'
import type { HTTPClient, PostClient, PaymentOutput } from '../types.js'

// A valid compressed secp256k1 public key (33 bytes, prefix 02).
const testPubKeyHex =
  '02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2'

// ---------------------------------------------------------------------------
// Mock HTTP helpers
// ---------------------------------------------------------------------------

/** Create a mock Response from JSON data. */
function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/** Create a mock Response from plain text. */
function textResponse(text: string, status = 200): Response {
  return new Response(text, { status })
}

/**
 * Build a mock HTTPClient that routes URLs to handler functions.
 * URL matching is done by checking if the requested URL ends with the
 * registered path (to handle rewriting https://domain/... to the handler).
 */
function mockHTTPClient(
  handlers: Record<string, () => Response>,
): HTTPClient {
  return {
    async get(url: string): Promise<Response> {
      for (const [path, handler] of Object.entries(handlers)) {
        if (url.includes(path)) {
          return handler()
        }
      }
      return new Response('Not Found', { status: 404 })
    },
  }
}

/** Build a mock PostClient that also supports POST. */
function mockPostClient(
  getHandlers: Record<string, () => Response>,
  postHandlers: Record<string, () => Response>,
): PostClient {
  const httpClient = mockHTTPClient(getHandlers)
  return {
    ...httpClient,
    async post(url: string, _contentType: string, _body: string): Promise<Response> {
      for (const [path, handler] of Object.entries(postHandlers)) {
        if (url.includes(path)) {
          return handler()
        }
      }
      return new Response('Not Found', { status: 404 })
    },
  }
}

/** Standard .well-known response with PKI capability. */
function wellKnownWithPKI(): Response {
  return jsonResponse({
    bsvalias: '1.0',
    capabilities: {
      pki: 'https://example.com/api/v1/bsvalias/pki/{alias}@{domain.tld}',
      f12f968c92d6:
        'https://example.com/api/v1/bsvalias/public-profile/{alias}@{domain.tld}',
    },
  })
}

/** Standard .well-known response with PKI + payment destination capabilities. */
function wellKnownWithPayment(): Response {
  return jsonResponse({
    bsvalias: '1.0',
    capabilities: {
      pki: 'https://example.com/api/v1/bsvalias/pki/{alias}@{domain.tld}',
      '2a40af698840':
        'https://example.com/api/v1/bsvalias/p2p-payment-destination/{alias}@{domain.tld}',
    },
  })
}

// ---------------------------------------------------------------------------
// discoverCapabilities
// ---------------------------------------------------------------------------

describe('discoverCapabilities', () => {
  it('discovers PKI and public profile capabilities', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': wellKnownWithPKI,
    })

    const caps = await discoverCapabilities('example.com', client)
    expect(caps.pki).not.toBe('')
    expect(caps.publicProfile).not.toBe('')
  })

  it('throws on empty domain', async () => {
    await expect(discoverCapabilities('')).rejects.toThrow(PaymailDiscoveryError)
  })

  it('throws on server error', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': () => textResponse('Internal Server Error', 500),
    })

    await expect(discoverCapabilities('example.com', client)).rejects.toThrow(
      PaymailDiscoveryError,
    )
  })

  it('throws on invalid JSON', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': () => textResponse('not json'),
    })

    await expect(discoverCapabilities('example.com', client)).rejects.toThrow(
      PaymailDiscoveryError,
    )
  })

  it('skips non-string capability values', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': () =>
        jsonResponse({
          bsvalias: '1.0',
          capabilities: {
            pki: 12345,
            f12f968c92d6: true,
            a9f510c16bde: ['not', 'a string'],
          },
        }),
    })

    const caps = await discoverCapabilities('example.com', client)
    expect(caps.pki).toBe('')
    expect(caps.publicProfile).toBe('')
    expect(caps.verifyPubKey).toBe('')
  })

  it('rejects non-HTTPS capability URLs', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': () =>
        jsonResponse({
          bsvalias: '1.0',
          capabilities: {
            pki: 'http://evil.com/pki/{alias}@{domain.tld}',
          },
        }),
    })

    const caps = await discoverCapabilities('example.com', client)
    expect(caps.pki).toBe('')
  })

  it('rejects capability URLs from different domains (SSRF)', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': () =>
        jsonResponse({
          bsvalias: '1.0',
          capabilities: {
            pki: 'https://evil.com/pki/{alias}@{domain.tld}',
          },
        }),
    })

    const caps = await discoverCapabilities('example.com', client)
    expect(caps.pki).toBe('')
  })

  it('accepts subdomain capability URLs', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': () =>
        jsonResponse({
          bsvalias: '1.0',
          capabilities: {
            pki: 'https://api.example.com/pki/{alias}@{domain.tld}',
          },
        }),
    })

    const caps = await discoverCapabilities('example.com', client)
    expect(caps.pki).not.toBe('')
  })

  it('throws on connection error', async () => {
    const client: HTTPClient = {
      async get(): Promise<Response> {
        throw new Error('connection refused')
      },
    }

    await expect(discoverCapabilities('example.com', client)).rejects.toThrow(
      PaymailDiscoveryError,
    )
  })
})

// ---------------------------------------------------------------------------
// resolvePKI
// ---------------------------------------------------------------------------

describe('resolvePKI', () => {
  it('resolves public key successfully', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': wellKnownWithPKI,
      '/api/v1/bsvalias/pki/': () =>
        jsonResponse({
          bsvalias: '1.0',
          handle: 'alice@example.com',
          pubkey: testPubKeyHex,
        }),
    })

    const pubKey = await resolvePKI('alice', 'example.com', client)
    expect(pubKey.length).toBe(33)
    expect(pubKey[0]).toBe(0x02)
  })

  it('throws on empty alias', async () => {
    await expect(resolvePKI('', 'example.com')).rejects.toThrow(PKIResolutionError)
  })

  it('throws on empty domain', async () => {
    await expect(resolvePKI('alice', '')).rejects.toThrow(PKIResolutionError)
  })

  it('throws on empty pubkey response', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': wellKnownWithPKI,
      '/api/v1/bsvalias/pki/': () =>
        jsonResponse({
          bsvalias: '1.0',
          handle: 'alice@example.com',
          pubkey: '',
        }),
    })

    await expect(resolvePKI('alice', 'example.com', client)).rejects.toThrow(
      PKIResolutionError,
    )
  })

  it('throws on invalid hex pubkey', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': wellKnownWithPKI,
      '/api/v1/bsvalias/pki/': () =>
        jsonResponse({
          bsvalias: '1.0',
          handle: 'alice@example.com',
          pubkey: 'zzzz',
        }),
    })

    await expect(resolvePKI('alice', 'example.com', client)).rejects.toThrow(
      InvalidPubKeyError,
    )
  })

  it('throws when no PKI capability', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': () =>
        jsonResponse({
          bsvalias: '1.0',
          capabilities: {},
        }),
    })

    await expect(resolvePKI('alice', 'example.com', client)).rejects.toThrow(
      PKIResolutionError,
    )
  })

  it('throws on PKI endpoint non-200', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': wellKnownWithPKI,
      '/api/v1/bsvalias/pki/': () => textResponse('not found', 404),
    })

    await expect(resolvePKI('alice', 'example.com', client)).rejects.toThrow(
      PKIResolutionError,
    )
  })

  it('throws on PKI endpoint invalid JSON', async () => {
    const client = mockHTTPClient({
      '/.well-known/bsvalias': wellKnownWithPKI,
      '/api/v1/bsvalias/pki/': () => textResponse('{garbled json!!!'),
    })

    await expect(resolvePKI('alice', 'example.com', client)).rejects.toThrow(
      PKIResolutionError,
    )
  })

  it('escapes template variables to prevent path traversal', async () => {
    let capturedURL = ''
    const client: HTTPClient = {
      async get(url: string): Promise<Response> {
        capturedURL = url
        if (url.includes('/.well-known/bsvalias')) {
          return wellKnownWithPKI()
        }
        // Return a valid PKI response so we can check the URL
        return jsonResponse({
          bsvalias: '1.0',
          handle: 'test@example.com',
          pubkey: testPubKeyHex,
        })
      },
    }

    await resolvePKI('test/../admin', 'example.com', client)
    // The ".." must be percent-encoded in the URL
    expect(capturedURL).not.toContain('test/../admin')
  })
})

// ---------------------------------------------------------------------------
// resolvePaymentDestination
// ---------------------------------------------------------------------------

describe('resolvePaymentDestination', () => {
  it('resolves payment outputs successfully', async () => {
    const outputs: PaymentOutput[] = [
      {
        script: '76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac',
        satoshis: 1000,
      },
    ]
    const client = mockPostClient(
      { '/.well-known/bsvalias': wellKnownWithPayment },
      {
        '/api/v1/bsvalias/p2p-payment-destination/': () =>
          jsonResponse({ outputs }),
      },
    )

    const result = await resolvePaymentDestination('alice', 'example.com', client)
    expect(result).toHaveLength(1)
    expect(result[0].script).toBe(
      '76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac',
    )
    expect(result[0].satoshis).toBe(1000)
  })

  it('resolves multiple outputs', async () => {
    const outputs: PaymentOutput[] = [
      {
        script: '76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac',
        satoshis: 500,
      },
      {
        script: '76a914aabbccddaabbccddaabbccddaabbccddaabbccdd88ac',
        satoshis: 500,
      },
    ]
    const client = mockPostClient(
      { '/.well-known/bsvalias': wellKnownWithPayment },
      {
        '/api/v1/bsvalias/p2p-payment-destination/': () =>
          jsonResponse({ outputs }),
      },
    )

    const result = await resolvePaymentDestination('alice', 'example.com', client)
    expect(result).toHaveLength(2)
    expect(result[0].satoshis).toBe(500)
    expect(result[1].satoshis).toBe(500)
  })

  it('throws on empty alias', async () => {
    await expect(
      resolvePaymentDestination('', 'example.com'),
    ).rejects.toThrow(AddressResolutionError)
  })

  it('throws on empty domain', async () => {
    await expect(
      resolvePaymentDestination('alice', ''),
    ).rejects.toThrow(AddressResolutionError)
  })

  it('throws when no payment destination capability', async () => {
    const client = mockPostClient(
      {
        '/.well-known/bsvalias': () =>
          jsonResponse({
            bsvalias: '1.0',
            capabilities: {
              pki: 'https://example.com/pki/{alias}@{domain.tld}',
            },
          }),
      },
      {},
    )

    await expect(
      resolvePaymentDestination('alice', 'example.com', client),
    ).rejects.toThrow(AddressResolutionError)
  })

  it('throws on empty outputs', async () => {
    const client = mockPostClient(
      { '/.well-known/bsvalias': wellKnownWithPayment },
      {
        '/api/v1/bsvalias/p2p-payment-destination/': () =>
          jsonResponse({ outputs: [] }),
      },
    )

    await expect(
      resolvePaymentDestination('alice', 'example.com', client),
    ).rejects.toThrow(AddressResolutionError)
  })
})
