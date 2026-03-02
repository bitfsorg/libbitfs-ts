// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import { InvalidURIError, InvalidPubKeyError } from './errors.js'
import { AddressType, type ParsedURI } from './types.js'

/** Hex-encoded length of a compressed secp256k1 public key (33 bytes = 66 hex chars). */
const COMPRESSED_PUB_KEY_HEX_LEN = 66

/** The bitfs:// URI scheme prefix. */
const BITFS_SCHEME = 'bitfs://'

/**
 * Parse a bitfs:// URI into its components.
 *
 * Detects address type based on:
 * - Contains '@' in authority -> Paymail
 * - Authority starts with hex pubkey prefix (02/03) and is 66 hex chars -> PubKey
 * - Otherwise -> DNSLink
 */
export function parseURI(uri: string): ParsedURI {
  if (uri === '') {
    throw new InvalidURIError('empty URI')
  }

  // Must start with bitfs://
  if (!uri.startsWith(BITFS_SCHEME)) {
    throw new InvalidURIError('scheme must be bitfs://')
  }

  // Parse manually since URL() doesn't handle non-standard schemes well.
  const rest = uri.slice(BITFS_SCHEME.length)
  if (rest === '') {
    throw new InvalidURIError('empty authority')
  }

  // Split authority from path
  let authority: string
  let path: string
  const slashIdx = rest.indexOf('/')
  if (slashIdx >= 0) {
    authority = rest.slice(0, slashIdx)
    path = rest.slice(slashIdx) // Keep leading slash
  } else {
    authority = rest
    path = ''
  }

  if (authority === '') {
    throw new InvalidURIError('empty authority')
  }

  const result: ParsedURI = {
    type: AddressType.DNSLink,
    alias: '',
    domain: '',
    pubKey: null,
    path,
    rawURI: uri,
  }

  // Detect address type
  if (authority.includes('@')) {
    // Paymail: alias@domain
    const atIdx = authority.indexOf('@')
    const alias = authority.slice(0, atIdx)
    const domain = authority.slice(atIdx + 1)
    if (alias === '' || domain === '') {
      throw new InvalidURIError(`invalid Paymail address "${authority}"`)
    }
    result.type = AddressType.Paymail
    result.alias = alias
    result.domain = domain
  } else if (isPubKeyHex(authority)) {
    // PubKey: 02/03 + 64 hex chars = 66 hex chars total
    const pubKeyBytes = hexToBytes(authority)
    result.type = AddressType.PubKey
    result.pubKey = pubKeyBytes
  } else {
    // DNSLink: plain domain
    result.type = AddressType.DNSLink
    result.domain = authority
  }

  return result
}

/**
 * Check if a string looks like a compressed secp256k1 public key in hex:
 * starts with "02" or "03" and is exactly 66 hex characters (33 bytes).
 */
export function isPubKeyHex(s: string): boolean {
  if (s.length !== COMPRESSED_PUB_KEY_HEX_LEN) {
    return false
  }
  if (!s.startsWith('02') && !s.startsWith('03')) {
    return false
  }
  // Verify all characters are valid hex
  return /^[0-9a-fA-F]+$/.test(s)
}

/**
 * Validate that raw bytes represent a valid compressed secp256k1 public key.
 * A compressed key is exactly 33 bytes with prefix 0x02 or 0x03.
 */
export function validateCompressedPubKey(pub: Uint8Array): void {
  if (pub.length !== 33) {
    throw new InvalidPubKeyError(`expected 33 bytes, got ${pub.length}`)
  }
  if (pub[0] !== 0x02 && pub[0] !== 0x03) {
    throw new InvalidPubKeyError(
      `invalid prefix byte 0x${pub[0].toString(16).padStart(2, '0')}`,
    )
  }
}

// ---------------------------------------------------------------------------
// Internal hex helpers
// ---------------------------------------------------------------------------

/** Decode a hex string to Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  const len = hex.length / 2
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/** Encode bytes to lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0')
  }
  return hex
}
