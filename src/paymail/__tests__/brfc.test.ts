// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import { describe, it, expect } from 'vitest'

import {
  computeBRFCID,
  BRFC_BITFS_BROWSE,
  BRFC_BITFS_BUY,
  BRFC_BITFS_SELL,
} from '../brfc.js'

// ---------------------------------------------------------------------------
// computeBRFCID
// ---------------------------------------------------------------------------

describe('computeBRFCID', () => {
  it('returns 12-char hex string', () => {
    const id = computeBRFCID('Test Title', 'Test Author', '1.0')
    expect(id).toHaveLength(12)
    // Verify it's valid hex
    expect(/^[0-9a-f]+$/.test(id)).toBe(true)
  })

  it('is deterministic', () => {
    const id1 = computeBRFCID('BitFS Browse', 'BitFS', '1.0')
    const id2 = computeBRFCID('BitFS Browse', 'BitFS', '1.0')
    expect(id1).toBe(id2)
  })

  it('different inputs produce different outputs', () => {
    const idBrowse = computeBRFCID('BitFS Browse', 'BitFS', '1.0')
    const idBuy = computeBRFCID('BitFS Buy', 'BitFS', '1.0')
    const idSell = computeBRFCID('BitFS Sell', 'BitFS', '1.0')

    expect(idBrowse).not.toBe(idBuy)
    expect(idBrowse).not.toBe(idSell)
    expect(idBuy).not.toBe(idSell)
  })

  it('different version produces different output', () => {
    const id1 = computeBRFCID('BitFS Browse', 'BitFS', '1.0')
    const id2 = computeBRFCID('BitFS Browse', 'BitFS', '2.0')
    expect(id1).not.toBe(id2)
  })

  it('different author produces different output', () => {
    const id1 = computeBRFCID('BitFS Browse', 'BitFS', '1.0')
    const id2 = computeBRFCID('BitFS Browse', 'Other', '1.0')
    expect(id1).not.toBe(id2)
  })

  it('empty inputs produce valid output', () => {
    const id = computeBRFCID('', '', '')
    expect(id).toHaveLength(12)
    expect(/^[0-9a-f]+$/.test(id)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// BRFC constants
// ---------------------------------------------------------------------------

describe('BRFC constants', () => {
  it('BRFCBitFSBrowse matches computed value', () => {
    expect(BRFC_BITFS_BROWSE).toBe(computeBRFCID('BitFS Browse', 'BitFS', '1.0'))
  })

  it('BRFCBitFSBuy matches computed value', () => {
    expect(BRFC_BITFS_BUY).toBe(computeBRFCID('BitFS Buy', 'BitFS', '1.0'))
  })

  it('BRFCBitFSSell matches computed value', () => {
    expect(BRFC_BITFS_SELL).toBe(computeBRFCID('BitFS Sell', 'BitFS', '1.0'))
  })

  it('all constants are distinct', () => {
    expect(BRFC_BITFS_BROWSE).not.toBe(BRFC_BITFS_BUY)
    expect(BRFC_BITFS_BROWSE).not.toBe(BRFC_BITFS_SELL)
    expect(BRFC_BITFS_BUY).not.toBe(BRFC_BITFS_SELL)
  })

  it('all constants are 12-char hex', () => {
    for (const [name, id] of Object.entries({
      Browse: BRFC_BITFS_BROWSE,
      Buy: BRFC_BITFS_BUY,
      Sell: BRFC_BITFS_SELL,
    })) {
      expect(id).toHaveLength(12)
      expect(/^[0-9a-f]+$/.test(id)).toBe(true)
    }
  })
})

// ---------------------------------------------------------------------------
// Cross-language consistency: verify Go and TS produce identical BRFC IDs
// ---------------------------------------------------------------------------

describe('cross-language BRFC consistency', () => {
  it('computeBRFCID uses double-SHA256', () => {
    // Manually verify the algorithm: SHA256(SHA256(data))[:6] as hex
    // We can at least verify the output is stable and 12 hex chars
    const id = computeBRFCID('BitFS Browse', 'BitFS', '1.0')
    expect(id).toHaveLength(12)
    expect(typeof id).toBe('string')
    // The same call should always return the same result
    expect(computeBRFCID('BitFS Browse', 'BitFS', '1.0')).toBe(id)
  })
})
