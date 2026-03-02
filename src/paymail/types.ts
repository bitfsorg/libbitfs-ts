// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

/**
 * AddressType represents the three BitFS addressing modes.
 *
 * - Paymail: bitfs://alias@domain/path
 * - DNSLink: bitfs://domain/path
 * - PubKey:  bitfs://02abcdef.../path
 */
export const AddressType = {
  /** Paymail address: bitfs://alias@domain/path */
  Paymail: 0,
  /** DNSLink address: bitfs://domain/path */
  DNSLink: 1,
  /** Direct public key: bitfs://02abcdef.../path */
  PubKey: 2,
} as const

export type AddressType = (typeof AddressType)[keyof typeof AddressType]

/** Human-readable label for an AddressType value. */
export function addressTypeString(t: AddressType): string {
  switch (t) {
    case AddressType.Paymail:
      return 'Paymail'
    case AddressType.DNSLink:
      return 'DNSLink'
    case AddressType.PubKey:
      return 'PubKey'
    default:
      return 'Unknown'
  }
}

/** A parsed bitfs:// URI. */
export interface ParsedURI {
  /** Which addressing mode the URI uses. */
  type: AddressType
  /** Paymail alias (empty for non-Paymail). */
  alias: string
  /** Domain name (empty for PubKey). */
  domain: string
  /** Raw compressed public key bytes (only for AddressPubKey). */
  pubKey: Uint8Array | null
  /** Path component after the authority (includes leading slash). */
  path: string
  /** Original URI string. */
  rawURI: string
}

/** Paymail server capabilities discovered from .well-known/bsvalias. */
export interface PaymailCapabilities {
  /** URL template for public key infrastructure. */
  pki: string
  /** URL template for profile info. */
  publicProfile: string
  /** URL template for key verification. */
  verifyPubKey: string
  /** URL template for P2P payment destination (BRFC 2a40af698840). */
  paymentDestination: string
}

/** PKI endpoint response. */
export interface PKIResponse {
  bsvalias: string
  handle: string
  pubkey: string
}

/** A single output in a P2P payment destination response. */
export interface PaymentOutput {
  /** Hex-encoded locking script. */
  script: string
  /** Amount in satoshis. */
  satoshis: number
}

/**
 * Minimal HTTP client interface for paymail resolution.
 * Allows test mocking without a real HTTP stack.
 */
export interface HTTPClient {
  get(url: string): Promise<Response>
}

/**
 * Extended HTTP client with POST capability.
 * Needed for P2P payment destination resolution.
 */
export interface PostClient extends HTTPClient {
  post(url: string, contentType: string, body: string): Promise<Response>
}
