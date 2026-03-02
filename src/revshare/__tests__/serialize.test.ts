import { describe, it, expect } from 'vitest'
import {
  serializeRegistry,
  deserializeRegistry,
  serializeShare,
  deserializeShare,
  serializeISOPool,
  deserializeISOPool,
  isISOActive,
  isLocked,
  findEntry,
} from '../index.js'
import type { RegistryState, RevShareEntry, ShareData, ISOPoolState } from '../index.js'

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

// --- Registry serialization ---

describe('serializeRegistry / deserializeRegistry', () => {
  it('round-trip: single entry', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 10000n,
      entries: [{ address: makeAddr(0xaa), share: 10000n }],
      modeFlags: 0,
    }
    const data = serializeRegistry(state)
    const decoded = deserializeRegistry(data)
    expect(decoded.nodeID).toEqual(state.nodeID)
    expect(decoded.totalShares).toBe(10000n)
    expect(decoded.entries).toHaveLength(1)
    expect(decoded.entries[0].address).toEqual(makeAddr(0xaa))
    expect(decoded.entries[0].share).toBe(10000n)
    expect(decoded.modeFlags).toBe(0)
  })

  it('round-trip: multiple entries', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x02),
      totalShares: 10000n,
      entries: [
        { address: makeAddr(0xaa), share: 3000n },
        { address: makeAddr(0xbb), share: 2000n },
        { address: makeAddr(0xcc), share: 5000n },
      ],
      modeFlags: 0x01, // ISO active
    }
    const data = serializeRegistry(state)
    const decoded = deserializeRegistry(data)
    expect(decoded.nodeID).toEqual(state.nodeID)
    expect(decoded.totalShares).toBe(10000n)
    expect(decoded.entries).toHaveLength(3)
    expect(decoded.modeFlags).toBe(0x01)
    for (let i = 0; i < state.entries.length; i++) {
      expect(decoded.entries[i].address).toEqual(state.entries[i].address)
      expect(decoded.entries[i].share).toBe(state.entries[i].share)
    }
  })

  it('round-trip: locked state', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x03),
      totalShares: 100n,
      entries: [{ address: makeAddr(0x01), share: 100n }],
      modeFlags: 0x03, // ISO active + locked
    }
    const data = serializeRegistry(state)
    const decoded = deserializeRegistry(data)
    expect(decoded.modeFlags).toBe(0x03)
    expect(isISOActive(decoded)).toBe(true)
    expect(isLocked(decoded)).toBe(true)
  })

  it('correct size: 2 entries = 101 bytes', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 10000n,
      entries: [
        { address: makeAddr(0xaa), share: 5000n },
        { address: makeAddr(0xbb), share: 5000n },
      ],
      modeFlags: 0,
    }
    const data = serializeRegistry(state)
    // 32 + 8 + 4 + 28*2 + 1 = 101
    expect(data.length).toBe(101)
  })

  it('zero entries: 45 bytes', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 0n,
      entries: [],
      modeFlags: 0,
    }
    const data = serializeRegistry(state)
    expect(data.length).toBe(45) // header(44) + trailer(1)
    const decoded = deserializeRegistry(data)
    expect(decoded.entries).toHaveLength(0)
  })

  it('100 entries', () => {
    const entries: RevShareEntry[] = Array.from({ length: 100 }, (_, i) => ({
      address: makeAddr(i),
      share: 100n,
    }))
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 10000n,
      entries,
      modeFlags: 0,
    }
    const data = serializeRegistry(state)
    expect(data.length).toBe(44 + 28 * 100 + 1)
    const decoded = deserializeRegistry(data)
    expect(decoded.entries).toHaveLength(100)
  })

  it('deserialize too short throws', () => {
    expect(() => deserializeRegistry(new Uint8Array([0x01, 0x02]))).toThrow(
      'invalid registry data',
    )
  })

  it('deserialize truncated entries throws', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 10000n,
      entries: [
        { address: makeAddr(0xaa), share: 5000n },
        { address: makeAddr(0xbb), share: 5000n },
      ],
      modeFlags: 0,
    }
    const data = serializeRegistry(state)
    // Remove last entry (28 bytes) + trailer (1 byte)
    expect(() =>
      deserializeRegistry(data.subarray(0, data.length - 29)),
    ).toThrow('invalid registry data')
  })

  it('deserialize exact minimum (45 bytes, 0 entries)', () => {
    const data = new Uint8Array(45)
    const decoded = deserializeRegistry(data)
    expect(decoded.entries).toHaveLength(0)
    expect(decoded.totalShares).toBe(0n)
  })

  it('mode flags: all combinations', () => {
    const combos: [number, boolean, boolean][] = [
      [0x00, false, false],
      [0x01, true, false],
      [0x02, false, true],
      [0x03, true, true],
    ]
    for (const [flags, iso, lock] of combos) {
      const state: RegistryState = {
        nodeID: makeNodeID(0x01),
        totalShares: 100n,
        entries: [{ address: makeAddr(0xaa), share: 100n }],
        modeFlags: flags,
      }
      const data = serializeRegistry(state)
      const decoded = deserializeRegistry(data)
      expect(isISOActive(decoded)).toBe(iso)
      expect(isLocked(decoded)).toBe(lock)
    }
  })

  it('nodeID preserved byte-by-byte', () => {
    const nodeID = new Uint8Array(32)
    for (let i = 0; i < 32; i++) nodeID[i] = i
    const state: RegistryState = {
      nodeID,
      totalShares: 1n,
      entries: [{ address: makeAddr(0x01), share: 1n }],
      modeFlags: 0,
    }
    const data = serializeRegistry(state)
    const decoded = deserializeRegistry(data)
    expect(decoded.nodeID).toEqual(nodeID)
  })

  it('large shares (max uint64)', () => {
    const MAX_U64 = (1n << 64n) - 1n
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: MAX_U64,
      entries: [
        { address: makeAddr(0xaa), share: MAX_U64 / 2n },
        { address: makeAddr(0xbb), share: MAX_U64 - MAX_U64 / 2n },
      ],
      modeFlags: 0,
    }
    const data = serializeRegistry(state)
    const decoded = deserializeRegistry(data)
    expect(decoded.totalShares).toBe(MAX_U64)
    expect(decoded.entries[0].share).toBe(MAX_U64 / 2n)
  })

  it('extra trailing bytes still deserializes', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 100n,
      entries: [{ address: makeAddr(0xaa), share: 100n }],
      modeFlags: 0,
    }
    const data = serializeRegistry(state)
    // Append extra bytes
    const extended = new Uint8Array(data.length + 3)
    extended.set(data)
    extended[data.length] = 0xff
    extended[data.length + 1] = 0xff
    extended[data.length + 2] = 0xff
    const decoded = deserializeRegistry(extended)
    expect(decoded.entries).toHaveLength(1)
  })

  it('44 bytes (missing trailer) throws', () => {
    expect(() => deserializeRegistry(new Uint8Array(44))).toThrow(
      'invalid registry data',
    )
  })

  it('entry addresses remain distinct', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 300n,
      entries: [
        { address: makeAddr(0x01), share: 100n },
        { address: makeAddr(0x02), share: 100n },
        { address: makeAddr(0x03), share: 100n },
      ],
      modeFlags: 0,
    }
    const data = serializeRegistry(state)
    const decoded = deserializeRegistry(data)
    for (let i = 0; i < decoded.entries.length; i++) {
      expect(decoded.entries[i].address).toEqual(makeAddr(i + 1))
    }
  })
})

// --- Share serialization ---

describe('serializeShare / deserializeShare', () => {
  it('round-trip', () => {
    const share: ShareData = { nodeID: makeNodeID(0x01), amount: 5000n }
    const data = serializeShare(share)
    expect(data.length).toBe(40)
    const decoded = deserializeShare(data)
    expect(decoded.nodeID).toEqual(share.nodeID)
    expect(decoded.amount).toBe(5000n)
  })

  it('wrong size throws', () => {
    expect(() => deserializeShare(new Uint8Array([0x01]))).toThrow(
      'invalid share data',
    )
  })

  it('zero amount', () => {
    const share: ShareData = { nodeID: makeNodeID(0x01), amount: 0n }
    const data = serializeShare(share)
    const decoded = deserializeShare(data)
    expect(decoded.amount).toBe(0n)
  })

  it('max amount (uint64 max)', () => {
    const MAX_U64 = (1n << 64n) - 1n
    const share: ShareData = { nodeID: makeNodeID(0xff), amount: MAX_U64 }
    const data = serializeShare(share)
    const decoded = deserializeShare(data)
    expect(decoded.amount).toBe(MAX_U64)
  })

  it('too long (41 bytes) throws', () => {
    expect(() => deserializeShare(new Uint8Array(41))).toThrow(
      'invalid share data',
    )
  })

  it('too short (39 bytes) throws', () => {
    expect(() => deserializeShare(new Uint8Array(39))).toThrow(
      'invalid share data',
    )
  })

  it('nodeID preserved', () => {
    const nodeID = new Uint8Array(32)
    for (let i = 0; i < 32; i++) nodeID[i] = (i * 7) & 0xff
    const share: ShareData = { nodeID, amount: 42n }
    const data = serializeShare(share)
    const decoded = deserializeShare(data)
    expect(decoded.nodeID).toEqual(nodeID)
    expect(decoded.amount).toBe(42n)
  })

  it('different nodeIDs produce different data', () => {
    const data1 = serializeShare({ nodeID: makeNodeID(0x01), amount: 100n })
    const data2 = serializeShare({ nodeID: makeNodeID(0x02), amount: 100n })
    expect(data1).not.toEqual(data2)
  })
})

// --- ISOPool serialization ---

describe('serializeISOPool / deserializeISOPool', () => {
  it('round-trip', () => {
    const pool: ISOPoolState = {
      nodeID: makeNodeID(0x01),
      remainingShares: 6000n,
      pricePerShare: 100n,
      creatorAddr: makeAddr(0xaa),
    }
    const data = serializeISOPool(pool)
    expect(data.length).toBe(68)
    const decoded = deserializeISOPool(data)
    expect(decoded.nodeID).toEqual(pool.nodeID)
    expect(decoded.remainingShares).toBe(6000n)
    expect(decoded.pricePerShare).toBe(100n)
    expect(decoded.creatorAddr).toEqual(makeAddr(0xaa))
  })

  it('wrong size throws', () => {
    expect(() => deserializeISOPool(new Uint8Array([0x01]))).toThrow(
      'invalid ISO pool data',
    )
  })

  it('zero values', () => {
    const pool: ISOPoolState = {
      nodeID: new Uint8Array(32),
      remainingShares: 0n,
      pricePerShare: 0n,
      creatorAddr: new Uint8Array(20),
    }
    const data = serializeISOPool(pool)
    expect(data.length).toBe(68)
    const decoded = deserializeISOPool(data)
    expect(decoded.remainingShares).toBe(0n)
    expect(decoded.pricePerShare).toBe(0n)
  })

  it('max values (uint64 max)', () => {
    const MAX_U64 = (1n << 64n) - 1n
    const pool: ISOPoolState = {
      nodeID: makeNodeID(0xff),
      remainingShares: MAX_U64,
      pricePerShare: MAX_U64,
      creatorAddr: makeAddr(0xff),
    }
    const data = serializeISOPool(pool)
    const decoded = deserializeISOPool(data)
    expect(decoded.remainingShares).toBe(MAX_U64)
    expect(decoded.pricePerShare).toBe(MAX_U64)
  })

  it('too short (67 bytes) throws', () => {
    expect(() => deserializeISOPool(new Uint8Array(67))).toThrow(
      'invalid ISO pool data',
    )
  })

  it('too long (69 bytes) throws', () => {
    expect(() => deserializeISOPool(new Uint8Array(69))).toThrow(
      'invalid ISO pool data',
    )
  })

  it('creatorAddr preserved', () => {
    const addr = new Uint8Array(20)
    for (let i = 0; i < 20; i++) addr[i] = (i * 13) & 0xff
    const pool: ISOPoolState = {
      nodeID: makeNodeID(0x01),
      remainingShares: 5000n,
      pricePerShare: 200n,
      creatorAddr: addr,
    }
    const data = serializeISOPool(pool)
    const decoded = deserializeISOPool(data)
    expect(decoded.creatorAddr).toEqual(addr)
  })

  it('nodeID preserved', () => {
    const nodeID = new Uint8Array(32)
    for (let i = 0; i < 32; i++) nodeID[i] = i
    const pool: ISOPoolState = {
      nodeID,
      remainingShares: 1n,
      pricePerShare: 1n,
      creatorAddr: makeAddr(0x01),
    }
    const data = serializeISOPool(pool)
    const decoded = deserializeISOPool(data)
    expect(decoded.nodeID).toEqual(nodeID)
  })
})

// --- findEntry ---

describe('findEntry', () => {
  it('finds existing entry', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 10000n,
      entries: [
        { address: makeAddr(0xaa), share: 3000n },
        { address: makeAddr(0xbb), share: 7000n },
      ],
      modeFlags: 0,
    }
    const [idx, entry] = findEntry(state, makeAddr(0xbb))
    expect(idx).toBe(1)
    expect(entry!.share).toBe(7000n)
  })

  it('returns -1 for not found', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 10000n,
      entries: [{ address: makeAddr(0xaa), share: 10000n }],
      modeFlags: 0,
    }
    const [idx, entry] = findEntry(state, makeAddr(0xff))
    expect(idx).toBe(-1)
    expect(entry).toBeUndefined()
  })

  it('finds first entry', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 10000n,
      entries: [
        { address: makeAddr(0xaa), share: 5000n },
        { address: makeAddr(0xbb), share: 5000n },
      ],
      modeFlags: 0,
    }
    const [idx, entry] = findEntry(state, makeAddr(0xaa))
    expect(idx).toBe(0)
    expect(entry!.share).toBe(5000n)
  })

  it('finds last entry', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 10000n,
      entries: [
        { address: makeAddr(0xaa), share: 3000n },
        { address: makeAddr(0xbb), share: 3000n },
        { address: makeAddr(0xcc), share: 4000n },
      ],
      modeFlags: 0,
    }
    const [idx, entry] = findEntry(state, makeAddr(0xcc))
    expect(idx).toBe(2)
    expect(entry!.share).toBe(4000n)
  })

  it('empty entries returns not found', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 0n,
      entries: [],
      modeFlags: 0,
    }
    const [idx, entry] = findEntry(state, makeAddr(0xaa))
    expect(idx).toBe(-1)
    expect(entry).toBeUndefined()
  })
})

// --- isISOActive / isLocked ---

describe('isISOActive / isLocked', () => {
  it('all flag combinations', () => {
    for (let flags = 0; flags < 4; flags++) {
      const state: RegistryState = {
        nodeID: makeNodeID(0x01),
        totalShares: 0n,
        entries: [],
        modeFlags: flags,
      }
      expect(isISOActive(state)).toBe((flags & 0x01) !== 0)
      expect(isLocked(state)).toBe((flags & 0x02) !== 0)
    }
  })

  it('high bits ignored', () => {
    const state: RegistryState = {
      nodeID: makeNodeID(0x01),
      totalShares: 0n,
      entries: [],
      modeFlags: 0xfc, // bits 2-7 set, bits 0-1 clear
    }
    expect(isISOActive(state)).toBe(false)
    expect(isLocked(state)).toBe(false)

    state.modeFlags = 0xff // all bits set
    expect(isISOActive(state)).toBe(true)
    expect(isLocked(state)).toBe(true)
  })
})
