import { describe, it, expect } from 'vitest'
import {
  distributeRevenue,
  validateShareConservation,
  ErrNoEntries,
  ErrZeroTotalShares,
  ErrShareSumMismatch,
  ErrOverflow,
  ErrShareConservationViolation,
} from '../index.js'
import type { RevShareEntry, ShareData } from '../index.js'

// --- Helpers ---

function makeAddr(seed: number): Uint8Array {
  const addr = new Uint8Array(20)
  addr.fill(seed)
  return addr
}

function makeNodeID(seed: number): Uint8Array {
  const id = new Uint8Array(32)
  id.fill(seed)
  return id
}

// --- distributeRevenue ---

describe('distributeRevenue', () => {
  it('distributes 1000 sat among 3 entries (40%, 30%, 30%)', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 4000n },
      { address: makeAddr(0xbb), share: 3000n },
      { address: makeAddr(0xcc), share: 3000n },
    ]
    const dists = distributeRevenue(1000n, entries, 10000n)
    expect(dists).toHaveLength(3)
    expect(dists[0].amount).toBe(400n)
    expect(dists[1].amount).toBe(300n)
    expect(dists[2].amount).toBe(300n)
    // Total must equal totalPayment
    const total = dists.reduce((sum, d) => sum + d.amount, 0n)
    expect(total).toBe(1000n)
  })

  it('distributes with remainder: 100 sat, 3 equal shares -> [33, 33, 34]', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 1n },
      { address: makeAddr(0xbb), share: 1n },
      { address: makeAddr(0xcc), share: 1n },
    ]
    const dists = distributeRevenue(100n, entries, 3n)
    expect(dists[0].amount).toBe(33n)
    expect(dists[1].amount).toBe(33n)
    expect(dists[2].amount).toBe(34n) // last gets remainder
  })

  it('single entry gets all', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 10000n },
    ]
    const dists = distributeRevenue(5000n, entries, 10000n)
    expect(dists).toHaveLength(1)
    expect(dists[0].amount).toBe(5000n)
  })

  it('zero total payment returns all zeros', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 5000n },
      { address: makeAddr(0xbb), share: 5000n },
    ]
    const dists = distributeRevenue(0n, entries, 10000n)
    expect(dists).toHaveLength(2)
    expect(dists[0].amount).toBe(0n)
    expect(dists[1].amount).toBe(0n)
  })

  it('throws on zero total shares', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 0n },
    ]
    expect(() => distributeRevenue(100n, entries, 0n)).toThrow(
      ErrZeroTotalShares().message,
    )
  })

  it('throws on empty entries', () => {
    expect(() => distributeRevenue(100n, [], 10000n)).toThrow(
      ErrNoEntries().message,
    )
  })

  it('exact division', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 3000n },
      { address: makeAddr(0xbb), share: 2000n },
      { address: makeAddr(0xcc), share: 5000n },
    ]
    const dists = distributeRevenue(10000n, entries, 10000n)
    expect(dists[0].amount).toBe(3000n)
    expect(dists[1].amount).toBe(2000n)
    expect(dists[2].amount).toBe(5000n)
  })

  it('two shareholders equal', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 5000n },
      { address: makeAddr(0xbb), share: 5000n },
    ]
    const dists = distributeRevenue(100n, entries, 10000n)
    expect(dists[0].amount).toBe(50n)
    expect(dists[1].amount).toBe(50n)
  })

  it('large payment', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 5000n },
      { address: makeAddr(0xbb), share: 5000n },
    ]
    const dists = distributeRevenue(1_000_000_000n, entries, 10000n)
    expect(dists[0].amount).toBe(500_000_000n)
    expect(dists[1].amount).toBe(500_000_000n)
  })

  it('single satoshi cannot be split - last gets all', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 3333n },
      { address: makeAddr(0xbb), share: 3333n },
      { address: makeAddr(0xcc), share: 3334n },
    ]
    const dists = distributeRevenue(1n, entries, 10000n)
    expect(dists[0].amount).toBe(0n)
    expect(dists[1].amount).toBe(0n)
    expect(dists[2].amount).toBe(1n)
  })

  it('uneven split: 100/3 = 33,33,34', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 1n },
      { address: makeAddr(0xbb), share: 1n },
      { address: makeAddr(0xcc), share: 1n },
    ]
    const dists = distributeRevenue(100n, entries, 3n)
    expect(dists[0].amount).toBe(33n)
    expect(dists[1].amount).toBe(33n)
    expect(dists[2].amount).toBe(34n)
  })

  it('tiny share vs large share', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 1n },
      { address: makeAddr(0xbb), share: 9999n },
    ]
    const dists = distributeRevenue(10000n, entries, 10000n)
    expect(dists[0].amount).toBe(1n)
    expect(dists[1].amount).toBe(9999n)
  })

  it('many entries (1000)', () => {
    const n = 1000
    const entries: RevShareEntry[] = Array.from({ length: n }, (_, i) => ({
      address: makeAddr(i % 256),
      share: 10n,
    }))
    const totalShares = BigInt(n) * 10n
    const dists = distributeRevenue(10000n, entries, totalShares)
    expect(dists).toHaveLength(n)
    const total = dists.reduce((sum, d) => sum + d.amount, 0n)
    expect(total).toBe(10000n)
  })

  it('addresses are preserved', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0x11), share: 5000n },
      { address: makeAddr(0x22), share: 5000n },
    ]
    const dists = distributeRevenue(100n, entries, 10000n)
    expect(dists[0].address).toEqual(makeAddr(0x11))
    expect(dists[1].address).toEqual(makeAddr(0x22))
  })

  it('total always conserved for payments 1..100', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 3333n },
      { address: makeAddr(0xbb), share: 3333n },
      { address: makeAddr(0xcc), share: 3334n },
    ]
    for (let p = 1n; p <= 100n; p++) {
      const dists = distributeRevenue(p, entries, 10000n)
      const total = dists.reduce((sum, d) => sum + d.amount, 0n)
      expect(total).toBe(p)
    }
  })

  it('5 equal shares with odd payment', () => {
    const entries: RevShareEntry[] = Array.from({ length: 5 }, (_, i) => ({
      address: makeAddr(i),
      share: 2000n,
    }))
    const dists = distributeRevenue(7n, entries, 10000n)
    const total = dists.reduce((sum, d) => sum + d.amount, 0n)
    expect(total).toBe(7n)
  })

  it('last entry gets all remainder when shares are tiny', () => {
    const entries: RevShareEntry[] = Array.from({ length: 5 }, (_, i) => ({
      address: makeAddr(i + 0xaa),
      share: 1n,
    }))
    // Payment=2, totalShares=5: each gets 2*1/5=0, last gets 2
    const dists = distributeRevenue(2n, entries, 5n)
    for (let i = 0; i < 4; i++) {
      expect(dists[i].amount).toBe(0n)
    }
    expect(dists[4].amount).toBe(2n)
  })

  it('throws on share sum mismatch', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 80n },
      { address: makeAddr(0xbb), share: 80n },
      { address: makeAddr(0xcc), share: 80n },
    ]
    expect(() => distributeRevenue(1000n, entries, 100n)).toThrow(
      'sum of entry shares does not equal total shares',
    )
  })

  it('throws on share sum overflow', () => {
    const MAX_U64 = (1n << 64n) - 1n
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: MAX_U64 },
      { address: makeAddr(0xbb), share: 1n },
    ]
    expect(() => distributeRevenue(1000n, entries, MAX_U64)).toThrow(
      'overflow',
    )
  })

  it('handles large multiplication (128-bit intermediate)', () => {
    const MAX_U64 = (1n << 64n) - 1n
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: MAX_U64 / 2n },
      { address: makeAddr(0xbb), share: MAX_U64 - MAX_U64 / 2n },
    ]
    const dists = distributeRevenue(MAX_U64, entries, MAX_U64)
    expect(dists[0].amount).toBe(MAX_U64 / 2n)
    expect(dists[1].amount).toBe(MAX_U64 - MAX_U64 / 2n)
  })

  it('128-bit intermediate: maxU64 * 10000 / 10000', () => {
    const MAX_U64 = (1n << 64n) - 1n
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 10000n },
    ]
    const dists = distributeRevenue(MAX_U64, entries, 10000n)
    expect(dists[0].amount).toBe(MAX_U64)
  })

  it('single share equals total', () => {
    const entries: RevShareEntry[] = [
      { address: makeAddr(0xaa), share: 1n },
    ]
    const dists = distributeRevenue(999n, entries, 1n)
    expect(dists[0].amount).toBe(999n)
  })
})

// --- validateShareConservation ---

describe('validateShareConservation', () => {
  it('balanced inputs/outputs pass (1:1 transfer)', () => {
    const nodeID = makeNodeID(0x01)
    const inputs: ShareData[] = [{ nodeID, amount: 3000n }]
    const outputs: ShareData[] = [{ nodeID, amount: 3000n }]
    expect(() => validateShareConservation(inputs, outputs)).not.toThrow()
  })

  it('balanced split (1:2)', () => {
    const nodeID = makeNodeID(0x01)
    const inputs: ShareData[] = [{ nodeID, amount: 3000n }]
    const outputs: ShareData[] = [
      { nodeID, amount: 2000n },
      { nodeID, amount: 1000n },
    ]
    expect(() => validateShareConservation(inputs, outputs)).not.toThrow()
  })

  it('balanced merge (2:1)', () => {
    const nodeID = makeNodeID(0x01)
    const inputs: ShareData[] = [
      { nodeID, amount: 2000n },
      { nodeID, amount: 1000n },
    ]
    const outputs: ShareData[] = [{ nodeID, amount: 3000n }]
    expect(() => validateShareConservation(inputs, outputs)).not.toThrow()
  })

  it('imbalanced throws - shares created', () => {
    const nodeID = makeNodeID(0x01)
    const inputs: ShareData[] = [{ nodeID, amount: 1000n }]
    const outputs: ShareData[] = [{ nodeID, amount: 2000n }]
    expect(() => validateShareConservation(inputs, outputs)).toThrow(
      'share conservation violated',
    )
  })

  it('imbalanced throws - shares destroyed', () => {
    const nodeID = makeNodeID(0x01)
    const inputs: ShareData[] = [{ nodeID, amount: 2000n }]
    const outputs: ShareData[] = [{ nodeID, amount: 1000n }]
    expect(() => validateShareConservation(inputs, outputs)).toThrow(
      'share conservation violated',
    )
  })

  it('both empty passes (0 == 0)', () => {
    expect(() => validateShareConservation([], [])).not.toThrow()
  })

  it('many to many', () => {
    const nodeID = makeNodeID(0x01)
    const inputs: ShareData[] = [
      { nodeID, amount: 1000n },
      { nodeID, amount: 2000n },
      { nodeID, amount: 3000n },
    ]
    const outputs: ShareData[] = [
      { nodeID, amount: 2500n },
      { nodeID, amount: 3500n },
    ]
    expect(() => validateShareConservation(inputs, outputs)).not.toThrow()
  })

  it('one input, nil outputs throws', () => {
    const nodeID = makeNodeID(0x01)
    const inputs: ShareData[] = [{ nodeID, amount: 1000n }]
    expect(() => validateShareConservation(inputs, [])).toThrow(
      'share conservation violated',
    )
  })

  it('nil inputs, one output throws', () => {
    const nodeID = makeNodeID(0x01)
    const outputs: ShareData[] = [{ nodeID, amount: 1000n }]
    expect(() => validateShareConservation([], outputs)).toThrow(
      'share conservation violated',
    )
  })

  it('large amounts', () => {
    const nodeID = makeNodeID(0x01)
    const MAX_U64 = (1n << 64n) - 1n
    const half = MAX_U64 / 2n
    const inputs: ShareData[] = [
      { nodeID, amount: half },
      { nodeID, amount: half },
    ]
    const outputs: ShareData[] = [
      { nodeID, amount: half },
      { nodeID, amount: half },
    ]
    expect(() => validateShareConservation(inputs, outputs)).not.toThrow()
  })

  it('single unit', () => {
    const nodeID = makeNodeID(0x01)
    const inputs: ShareData[] = [{ nodeID, amount: 1n }]
    const outputs: ShareData[] = [{ nodeID, amount: 1n }]
    expect(() => validateShareConservation(inputs, outputs)).not.toThrow()
  })

  it('off by one throws', () => {
    const nodeID = makeNodeID(0x01)
    const inputs: ShareData[] = [{ nodeID, amount: 1000n }]

    expect(() =>
      validateShareConservation(inputs, [{ nodeID, amount: 1001n }]),
    ).toThrow('share conservation violated')

    expect(() =>
      validateShareConservation(inputs, [{ nodeID, amount: 999n }]),
    ).toThrow('share conservation violated')
  })

  it('overflow detection in inputs', () => {
    const nodeID = makeNodeID(0x01)
    const MAX_U64 = (1n << 64n) - 1n
    const inputs: ShareData[] = [
      { nodeID, amount: MAX_U64 },
      { nodeID, amount: 1n },
    ]
    const outputs: ShareData[] = [{ nodeID, amount: 0n }]
    expect(() => validateShareConservation(inputs, outputs)).toThrow(
      'overflow',
    )
  })
})
