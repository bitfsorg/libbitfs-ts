// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import {
  PaymailDiscoveryError,
  PKIResolutionError,
  InvalidPubKeyError,
  AddressResolutionError,
} from './errors.js'
import type {
  HTTPClient,
  PostClient,
  PaymailCapabilities,
  PKIResponse,
  PaymentOutput,
} from './types.js'
import { validateCompressedPubKey } from './uri.js'
import { hexToBytes } from '../util.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum allowed response body size for Paymail HTTP requests (1 MB). */
export const MAX_PAYMAIL_RESPONSE_SIZE = 1 << 20

/** Known Paymail capability keys / BRFC IDs. */
const CAP_PKI = 'pki'
const CAP_PUBLIC_PROFILE = 'f12f968c92d6'
const CAP_VERIFY_PUB_KEY = 'a9f510c16bde'
const CAP_PAYMENT_DESTINATION = '2a40af698840'

/** Alternate PKI BRFC ID used by some servers. */
const CAP_PKI_FULL = '6745385c3fc0'

// ---------------------------------------------------------------------------
// Default HTTP client using global fetch()
// ---------------------------------------------------------------------------

/** Default HTTP client backed by the global `fetch` function. */
export const defaultHTTPClient: HTTPClient = {
  async get(url: string): Promise<Response> {
    return fetch(url, { signal: AbortSignal.timeout(30_000) })
  },
}

/** Default POST client backed by the global `fetch` function. */
export const defaultPostClient: PostClient = {
  async get(url: string): Promise<Response> {
    return fetch(url, { signal: AbortSignal.timeout(30_000) })
  },
  async post(url: string, contentType: string, body: string): Promise<Response> {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': contentType },
      body,
      signal: AbortSignal.timeout(30_000),
    })
  },
}

// ---------------------------------------------------------------------------
// SSRF mitigation
// ---------------------------------------------------------------------------

/**
 * Validate that a capability URL's host matches the original domain
 * or is a subdomain of it. This prevents SSRF via server-controlled
 * URL templates.
 */
function validateCapabilityHost(capHost: string, originalDomain: string): boolean {
  const ch = capHost.toLowerCase()
  const od = originalDomain.toLowerCase()
  return ch === od || ch.endsWith('.' + od)
}

// ---------------------------------------------------------------------------
// Bounded body reader
// ---------------------------------------------------------------------------

async function readBoundedBody(resp: Response, maxSize: number, label: string): Promise<string> {
  const contentLength = resp.headers.get('content-length')
  if (contentLength && parseInt(contentLength, 10) > maxSize) {
    throw new PaymailDiscoveryError(`${label} response exceeds maximum size`)
  }
  const reader = resp.body?.getReader()
  if (!reader) {
    return resp.text()
  }
  const chunks: Uint8Array[] = []
  let totalBytes = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      totalBytes += value.length
      if (totalBytes > maxSize) {
        throw new PaymailDiscoveryError(`${label} response exceeds maximum size`)
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const combined = new Uint8Array(totalBytes)
  let offset = 0
  for (const chunk of chunks) {
    combined.set(chunk, offset)
    offset += chunk.length
  }
  return new TextDecoder().decode(combined)
}

// ---------------------------------------------------------------------------
// Capability discovery
// ---------------------------------------------------------------------------

/** Well-known response JSON structure. */
interface WellKnownResponse {
  bsvalias: string
  capabilities: Record<string, unknown>
}

/**
 * Fetch .well-known/bsvalias from a domain and return the Paymail server capabilities.
 */
export async function discoverCapabilities(
  domain: string,
  client: HTTPClient = defaultHTTPClient,
): Promise<PaymailCapabilities> {
  if (domain === '') {
    throw new PaymailDiscoveryError('empty domain')
  }

  const wkURL = `https://${domain}/.well-known/bsvalias`
  let resp: Response
  try {
    resp = await client.get(wkURL)
  } catch (err: unknown) {
    throw new PaymailDiscoveryError(`GET ${wkURL}: ${String(err)}`)
  }

  if (!resp.ok) {
    throw new PaymailDiscoveryError(`GET ${wkURL} returned status ${resp.status}`)
  }

  let bodyText: string
  try {
    bodyText = await readBoundedBody(resp, MAX_PAYMAIL_RESPONSE_SIZE, 'discovery')
  } catch (err: unknown) {
    if (err instanceof PaymailDiscoveryError) throw err
    throw new PaymailDiscoveryError(`reading response: ${String(err)}`)
  }

  let wk: WellKnownResponse
  try {
    wk = JSON.parse(bodyText) as WellKnownResponse
  } catch (err: unknown) {
    throw new PaymailDiscoveryError(`parsing JSON: ${String(err)}`)
  }

  const caps: PaymailCapabilities = {
    pki: '',
    publicProfile: '',
    verifyPubKey: '',
    paymentDestination: '',
  }

  if (!wk.capabilities || typeof wk.capabilities !== 'object') {
    return caps
  }

  for (const [key, val] of Object.entries(wk.capabilities)) {
    if (typeof val !== 'string') {
      continue
    }
    const urlStr = val

    // Validate URL is well-formed and uses HTTPS
    let parsed: URL
    try {
      parsed = new URL(urlStr)
    } catch {
      continue
    }
    if (parsed.protocol !== 'https:') {
      continue
    }

    // SSRF mitigation: capability URL host must match the original domain
    // or be a subdomain of it.
    if (!validateCapabilityHost(parsed.hostname, domain)) {
      continue
    }

    switch (key) {
      case CAP_PKI:
      case CAP_PKI_FULL:
        caps.pki = urlStr
        break
      case CAP_PUBLIC_PROFILE:
        caps.publicProfile = urlStr
        break
      case CAP_VERIFY_PUB_KEY:
        caps.verifyPubKey = urlStr
        break
      case CAP_PAYMENT_DESTINATION:
        caps.paymentDestination = urlStr
        break
    }
  }

  return caps
}

// ---------------------------------------------------------------------------
// PKI resolution
// ---------------------------------------------------------------------------

/**
 * Resolve a Paymail alias to its compressed public key bytes via the PKI capability.
 */
export async function resolvePKI(
  alias: string,
  domain: string,
  client: HTTPClient = defaultHTTPClient,
): Promise<Uint8Array> {
  if (alias === '' || domain === '') {
    throw new PKIResolutionError('alias and domain are required')
  }

  const caps = await discoverCapabilities(domain, client).catch((err: unknown) => {
    throw new PKIResolutionError(String(err))
  })

  if (caps.pki === '') {
    throw new PKIResolutionError(`no PKI capability found for ${domain}`)
  }

  // Build PKI URL from template, escaping variables to prevent path traversal.
  let pkiURL = caps.pki
    .replace('{alias}', encodeURIComponent(alias))
    .replace('{domain.tld}', encodeURIComponent(domain))

  let resp: Response
  try {
    resp = await client.get(pkiURL)
  } catch (err: unknown) {
    throw new PKIResolutionError(`GET ${pkiURL}: ${String(err)}`)
  }

  if (!resp.ok) {
    throw new PKIResolutionError(`GET ${pkiURL} returned status ${resp.status}`)
  }

  let bodyText: string
  try {
    bodyText = await readBoundedBody(resp, MAX_PAYMAIL_RESPONSE_SIZE, 'PKI')
  } catch (err: unknown) {
    if (err instanceof PaymailDiscoveryError) throw new PKIResolutionError(err.message)
    throw new PKIResolutionError(`reading response: ${String(err)}`)
  }

  let pki: PKIResponse
  try {
    pki = JSON.parse(bodyText) as PKIResponse
  } catch (err: unknown) {
    throw new PKIResolutionError(`parsing PKI response: ${String(err)}`)
  }

  if (!pki.pubkey || pki.pubkey === '') {
    throw new PKIResolutionError('empty public key in response')
  }

  let pubKeyBytes: Uint8Array
  try {
    pubKeyBytes = hexToBytes(pki.pubkey)
  } catch (err: unknown) {
    throw new InvalidPubKeyError(`invalid hex public key: ${String(err)}`)
  }

  validateCompressedPubKey(pubKeyBytes)

  return pubKeyBytes
}

// ---------------------------------------------------------------------------
// Payment destination resolution
// ---------------------------------------------------------------------------

/** JSON envelope returned by the payment destination endpoint. */
interface PaymentDestinationResponse {
  outputs: PaymentOutput[]
}

/**
 * Resolve a Paymail alias to P2P payment destination outputs.
 */
export async function resolvePaymentDestination(
  alias: string,
  domain: string,
  client: PostClient = defaultPostClient,
): Promise<PaymentOutput[]> {
  if (alias === '' || domain === '') {
    throw new AddressResolutionError('alias and domain are required')
  }

  const caps = await discoverCapabilities(domain, client).catch((err: unknown) => {
    throw new AddressResolutionError(String(err))
  })

  if (caps.paymentDestination === '') {
    throw new AddressResolutionError(
      `no payment destination capability found for ${domain}`,
    )
  }

  // Build URL from template
  let destURL = caps.paymentDestination
    .replace('{alias}', encodeURIComponent(alias))
    .replace('{domain.tld}', encodeURIComponent(domain))

  let resp: Response
  try {
    resp = await client.post(
      destURL,
      'application/json',
      JSON.stringify({ senderName: 'BitFS', purpose: 'revshare' }),
    )
  } catch (err: unknown) {
    throw new AddressResolutionError(`POST ${destURL}: ${String(err)}`)
  }

  if (!resp.ok) {
    throw new AddressResolutionError(
      `POST ${destURL} returned status ${resp.status}`,
    )
  }

  let bodyText: string
  try {
    bodyText = await readBoundedBody(resp, MAX_PAYMAIL_RESPONSE_SIZE, 'payment destination')
  } catch (err: unknown) {
    if (err instanceof PaymailDiscoveryError) throw new AddressResolutionError(err.message)
    throw new AddressResolutionError(`reading response: ${String(err)}`)
  }

  let destResp: PaymentDestinationResponse
  try {
    destResp = JSON.parse(bodyText) as PaymentDestinationResponse
  } catch (err: unknown) {
    throw new AddressResolutionError(`parsing response: ${String(err)}`)
  }

  if (!destResp.outputs || destResp.outputs.length === 0) {
    throw new AddressResolutionError('no outputs in response')
  }

  return destResp.outputs
}

