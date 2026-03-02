// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import { sha256 } from '@noble/hashes/sha256'

/**
 * Compute a BRFC (Bitcoin Request for Comments) ID per the BRC standard.
 *
 * The ID is derived from the double-SHA256 hash of the concatenation
 * of title, author, and version strings, truncated to the first 6 bytes
 * (12 hex characters).
 *
 *   ID = hex(SHA256d(title + author + version))[:12]
 *
 * SHA256d denotes SHA256(SHA256(x)).
 */
export function computeBRFCID(title: string, author: string, version: string): string {
  const data = new TextEncoder().encode(title + author + version)
  const first = sha256(data)
  const second = sha256(first)
  // Take first 6 bytes (12 hex chars)
  let hex = ''
  for (let i = 0; i < 6; i++) {
    hex += second[i].toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * BitFS-specific BRFC capability IDs, advertised in the Paymail
 * .well-known/bsvalias response to signal BitFS protocol support.
 */
export const BRFC_BITFS_BROWSE = computeBRFCID('BitFS Browse', 'BitFS', '1.0')
export const BRFC_BITFS_BUY = computeBRFCID('BitFS Buy', 'BitFS', '1.0')
export const BRFC_BITFS_SELL = computeBRFCID('BitFS Sell', 'BitFS', '1.0')
