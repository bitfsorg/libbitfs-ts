import { describe, it, expect } from 'vitest'
import {
  serializeHeader,
  deserializeHeader,
  computeHeaderHash,
  compactToTarget,
  compactToBigInt,
  workForTarget,
  cumulativeWork,
  verifyPoW,
  verifyHeaderChain,
  verifyHeaderChainWithWork,
  validateMinDifficulty,
  validateDifficultyTransition,
  minBitsForNetwork,
  MAINNET_MIN_BITS,
  TESTNET_MIN_BITS,
  REGTEST_MIN_BITS,
} from '../header.js'
import { doubleHash } from '../merkle.js'
import { SpvError } from '../errors.js'
import { BLOCK_HEADER_SIZE, HASH_SIZE, Network } from '../types.js'
import type { BlockHeader } from '../types.js'
import { MemHeaderStore } from '../store.js'

// --- Helpers ---

/** Creates a 32-byte array filled with a single seed byte. */
function makeHash(seed: number): Uint8Array {
  const h = new Uint8Array(32)
  h.fill(seed)
  return h
}

/** Creates a 32-byte double-SHA256 hash of a single seed byte. */
function makeTxHash(seed: number): Uint8Array {
  return doubleHash(new Uint8Array([seed]))
}

/**
 * Builds a test header and mines a valid nonce (regtest difficulty 0x207fffff).
 */
function buildTestHeader(height: number, prevBlock: Uint8Array, merkleRoot: Uint8Array): BlockHeader {
  const h: BlockHeader = {
    version: 1,
    prevBlock,
    merkleRoot,
    timestamp: 1700000000,
    bits: 0x207fffff,  // Regtest target: easy PoW
    nonce: 0,
    height,
    hash: new Uint8Array(0),
  }

  // Mine a valid nonce
  for (let nonce = 0; ; nonce++) {
    h.nonce = nonce
    h.hash = computeHeaderHash(h)
    try {
      verifyPoW(h)
      break
    } catch {
      // continue mining
    }
  }
  return h
}

/** Asserts that error is SpvError with given code. */
function expectSpvError(fn: () => void, code: string) {
  try {
    fn()
    expect.fail('expected to throw')
  } catch (e) {
    expect(e).toBeInstanceOf(SpvError)
    expect((e as SpvError).code).toBe(code)
  }
}

async function expectSpvErrorAsync(promise: Promise<unknown>, code: string) {
  try {
    await promise
    expect.fail('expected to reject')
  } catch (e) {
    expect(e).toBeInstanceOf(SpvError)
    expect((e as SpvError).code).toBe(code)
  }
}

// --- SerializeHeader / DeserializeHeader tests ---

describe('serializeHeader', () => {
  it('produces 80 bytes', () => {
    const h: BlockHeader = {
      version: 2,
      prevBlock: makeHash(0xaa),
      merkleRoot: makeHash(0xbb),
      timestamp: 1700000000,
      bits: 0x1d00ffff,
      nonce: 42,
      height: 0,
      hash: new Uint8Array(0),
    }

    const data = serializeHeader(h)
    expect(data.length).toBe(BLOCK_HEADER_SIZE)

    // Verify version (little-endian)
    const view = new DataView(data.buffer)
    expect(view.getInt32(0, true)).toBe(2)

    // Verify prevBlock
    expect(new Uint8Array(data.subarray(4, 36))).toEqual(makeHash(0xaa))

    // Verify merkleRoot
    expect(new Uint8Array(data.subarray(36, 68))).toEqual(makeHash(0xbb))

    // Verify timestamp
    expect(view.getUint32(68, true)).toBe(1700000000)

    // Verify bits
    expect(view.getUint32(72, true)).toBe(0x1d00ffff)

    // Verify nonce
    expect(view.getUint32(76, true)).toBe(42)
  })
})

describe('deserializeHeader', () => {
  it('decodes fields correctly', () => {
    const original: BlockHeader = {
      version: 536870912,
      prevBlock: makeHash(0x11),
      merkleRoot: makeHash(0x22),
      timestamp: 1700000000,
      bits: 0x1d00ffff,
      nonce: 987654321,
      height: 0,
      hash: new Uint8Array(0),
    }

    const data = serializeHeader(original)
    const decoded = deserializeHeader(data)

    expect(decoded.version).toBe(original.version)
    expect(decoded.prevBlock).toEqual(original.prevBlock)
    expect(decoded.merkleRoot).toEqual(original.merkleRoot)
    expect(decoded.timestamp).toBe(original.timestamp)
    expect(decoded.bits).toBe(original.bits)
    expect(decoded.nonce).toBe(original.nonce)
    expect(decoded.hash.length).toBe(32)
  })

  it('throws on invalid length', () => {
    expectSpvError(() => deserializeHeader(new Uint8Array(0)), 'ERR_INVALID_HEADER')
    expectSpvError(() => deserializeHeader(new Uint8Array(79)), 'ERR_INVALID_HEADER')
    expectSpvError(() => deserializeHeader(new Uint8Array(81)), 'ERR_INVALID_HEADER')
    expectSpvError(() => deserializeHeader(new Uint8Array(40)), 'ERR_INVALID_HEADER')
  })
})

describe('header round-trip', () => {
  it('serialize then deserialize preserves all fields', () => {
    const h: BlockHeader = {
      version: 1,
      prevBlock: makeTxHash(0x01),
      merkleRoot: makeTxHash(0x02),
      timestamp: 1700000000,
      bits: 0x1d00ffff,
      nonce: 0xdeadbeef,
      height: 0,
      hash: new Uint8Array(0),
    }

    const data = serializeHeader(h)
    const decoded = deserializeHeader(data)

    expect(decoded.version).toBe(h.version)
    expect(decoded.prevBlock).toEqual(h.prevBlock)
    expect(decoded.merkleRoot).toEqual(h.merkleRoot)
    expect(decoded.timestamp).toBe(h.timestamp)
    expect(decoded.bits).toBe(h.bits)
    expect(decoded.nonce).toBe(h.nonce)
  })
})

describe('computeHeaderHash', () => {
  it('returns 32-byte hash', () => {
    const h: BlockHeader = {
      version: 1,
      prevBlock: makeHash(0x00),
      merkleRoot: makeHash(0x11),
      timestamp: 1700000000,
      bits: 0x1d00ffff,
      nonce: 42,
      height: 0,
      hash: new Uint8Array(0),
    }

    const hash = computeHeaderHash(h)
    expect(hash.length).toBe(32)

    // Same header should produce same hash
    const hash2 = computeHeaderHash(h)
    expect(hash).toEqual(hash2)
  })
})

// --- CompactToTarget tests ---

describe('compactToTarget', () => {
  it('mainnet genesis bits 0x1d00ffff', () => {
    const target = compactToTarget(0x1d00ffff)
    expect(target.length).toBe(32)
    // exponent=0x1d=29, mantissa=0x00ffff
    // pos = 32 - 29 = 3
    expect(target[3]).toBe(0x00)
    expect(target[4]).toBe(0xff)
    expect(target[5]).toBe(0xff)
    // Everything after should be zero
    for (let i = 6; i < 32; i++) {
      expect(target[i]).toBe(0)
    }
  })

  it('regtest bits 0x207fffff', () => {
    const target = compactToTarget(0x207fffff)
    expect(target.length).toBe(32)
    // exponent=0x20=32, pos=0
    expect(target[0]).toBe(0x7f)
    expect(target[1]).toBe(0xff)
    expect(target[2]).toBe(0xff)
  })

  it('negative flag produces zero target', () => {
    const target = compactToTarget(0x1d80ffff)
    for (let i = 0; i < 32; i++) {
      expect(target[i]).toBe(0)
    }
  })

  it('small exponent (<=3)', () => {
    const target = compactToTarget(0x03123456)
    expect(target[29]).toBe(0x12)
    expect(target[30]).toBe(0x34)
    expect(target[31]).toBe(0x56)
  })
})

describe('compactToBigInt', () => {
  it('mainnet genesis bits', () => {
    const target = compactToBigInt(0x1d00ffff)
    expect(target > 0n).toBe(true)
  })

  it('regtest bits', () => {
    const target = compactToBigInt(0x207fffff)
    expect(target > 0n).toBe(true)
    // Regtest target should be much easier (larger) than mainnet
    const mainnetTarget = compactToBigInt(0x1d00ffff)
    expect(target > mainnetTarget).toBe(true)
  })

  it('negative flag returns 0', () => {
    expect(compactToBigInt(0x1d80ffff)).toBe(0n)
  })
})

describe('workForTarget', () => {
  it('harder difficulty (smaller target) produces more work', () => {
    const hardWork = workForTarget(0x1d00ffff)
    const easyWork = workForTarget(0x207fffff)
    expect(hardWork > easyWork).toBe(true)
  })

  it('zero target returns 0', () => {
    expect(workForTarget(0x1d800000)).toBe(0n)
  })
})

describe('cumulativeWork', () => {
  it('sums work across headers', () => {
    const h = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    const total = cumulativeWork([h, h])
    const single = workForTarget(h.bits)
    expect(total).toBe(single * 2n)
  })

  it('empty headers returns 0', () => {
    expect(cumulativeWork([])).toBe(0n)
  })
})

// --- PoW verification tests ---

describe('verifyPoW', () => {
  it('valid regtest header passes', () => {
    const h = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    expect(() => verifyPoW(h)).not.toThrow()
  })

  it('tampered nonce fails', () => {
    const h = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    // Set hash to all 0xFF (maximum value, definitely > any target)
    h.hash = new Uint8Array(32).fill(0xff)
    expectSpvError(() => verifyPoW(h), 'ERR_INSUFFICIENT_POW')
  })

  it('computes hash if not set', () => {
    const h = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    const originalHash = new Uint8Array(h.hash)
    h.hash = new Uint8Array(0)  // clear it
    expect(() => verifyPoW(h)).not.toThrow()
    // Restore and verify same result
    h.hash = originalHash
    expect(() => verifyPoW(h)).not.toThrow()
  })
})

// --- Network difficulty validation ---

describe('minBitsForNetwork', () => {
  it('returns correct values', () => {
    expect(minBitsForNetwork(Network.Mainnet)).toBe(MAINNET_MIN_BITS)
    expect(minBitsForNetwork(Network.Testnet)).toBe(TESTNET_MIN_BITS)
    expect(minBitsForNetwork(Network.Regtest)).toBe(REGTEST_MIN_BITS)
  })
})

describe('validateMinDifficulty', () => {
  it('regtest header passes for regtest network', () => {
    const h = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    expect(() => validateMinDifficulty(h, Network.Regtest)).not.toThrow()
  })

  it('regtest header fails for mainnet network', () => {
    const h = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    expectSpvError(() => validateMinDifficulty(h, Network.Mainnet), 'ERR_DIFFICULTY_TOO_LOW')
  })
})

describe('validateDifficultyTransition', () => {
  it('same difficulty passes', () => {
    const h1 = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    const h2 = buildTestHeader(1, h1.hash, makeHash(0x22))
    expect(() => validateDifficultyTransition(h1, h2)).not.toThrow()
  })
})

// --- Header chain verification ---

describe('verifyHeaderChain', () => {
  it('empty chain passes', () => {
    expect(() => verifyHeaderChain([])).not.toThrow()
  })

  it('single valid header passes', () => {
    const h = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    expect(() => verifyHeaderChain([h])).not.toThrow()
  })

  it('two linked headers pass', () => {
    const h0 = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    const h1 = buildTestHeader(1, h0.hash, makeHash(0x22))
    expect(() => verifyHeaderChain([h0, h1])).not.toThrow()
  })

  it('three linked headers pass', () => {
    const h0 = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    const h1 = buildTestHeader(1, h0.hash, makeHash(0x22))
    const h2 = buildTestHeader(2, h1.hash, makeHash(0x33))
    expect(() => verifyHeaderChain([h0, h1, h2])).not.toThrow()
  })

  it('broken chain throws', () => {
    const h0 = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    const h1 = buildTestHeader(1, makeHash(0xff), makeHash(0x22)) // wrong prevBlock
    expectSpvError(() => verifyHeaderChain([h0, h1]), 'ERR_CHAIN_BROKEN')
  })

  it('invalid PoW header fails', () => {
    const h: BlockHeader = {
      version: 1,
      prevBlock: makeHash(0x00),
      merkleRoot: makeHash(0x11),
      timestamp: 1700000000,
      bits: 0x207fffff,
      nonce: 0,
      height: 0,
      hash: new Uint8Array(32).fill(0xff), // invalid hash
    }
    expectSpvError(() => verifyHeaderChain([h]), 'ERR_INSUFFICIENT_POW')
  })
})

describe('verifyHeaderChainWithWork', () => {
  it('empty chain returns zero work', () => {
    const result = verifyHeaderChainWithWork([], Network.Regtest)
    expect(result.cumulativeWork).toBe(0n)
  })

  it('single header returns its work', () => {
    const h = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    const result = verifyHeaderChainWithWork([h], Network.Regtest)
    expect(result.cumulativeWork).toBe(workForTarget(h.bits))
  })

  it('linked chain accumulates work', () => {
    const h0 = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    const h1 = buildTestHeader(1, h0.hash, makeHash(0x22))
    const result = verifyHeaderChainWithWork([h0, h1], Network.Regtest)
    expect(result.cumulativeWork).toBe(workForTarget(h0.bits) + workForTarget(h1.bits))
  })

  it('broken chain throws', () => {
    const h0 = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    const h1 = buildTestHeader(1, makeHash(0xff), makeHash(0x22))
    expectSpvError(() => verifyHeaderChainWithWork([h0, h1], Network.Regtest), 'ERR_CHAIN_BROKEN')
  })
})

// --- MemHeaderStore tests ---

describe('MemHeaderStore', () => {
  it('putHeader + getHeader round-trip', async () => {
    const store = new MemHeaderStore()
    const h = buildTestHeader(0, makeHash(0x00), makeHash(0x11))

    await store.putHeader(h)
    const got = await store.getHeader(h.hash)
    expect(got).not.toBeNull()
    expect(got!.version).toBe(h.version)
    expect(got!.prevBlock).toEqual(h.prevBlock)
    expect(got!.nonce).toBe(h.nonce)
  })

  it('getHeader returns null for unknown hash', async () => {
    const store = new MemHeaderStore()
    const got = await store.getHeader(makeHash(0xff))
    expect(got).toBeNull()
  })

  it('getHeaderByHeight works', async () => {
    const store = new MemHeaderStore()
    const h0 = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    const h1 = buildTestHeader(5, h0.hash, makeHash(0x22))

    await store.putHeader(h0)
    await store.putHeader(h1)

    const got0 = await store.getHeaderByHeight(0)
    expect(got0).not.toBeNull()
    expect(got0!.nonce).toBe(h0.nonce)

    const got5 = await store.getHeaderByHeight(5)
    expect(got5).not.toBeNull()
    expect(got5!.nonce).toBe(h1.nonce)

    const gotMissing = await store.getHeaderByHeight(99)
    expect(gotMissing).toBeNull()
  })

  it('getTip returns highest-height header', async () => {
    const store = new MemHeaderStore()

    const tip0 = await store.getTip()
    expect(tip0).toBeNull()

    const h0 = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    const h1 = buildTestHeader(5, h0.hash, makeHash(0x22))

    await store.putHeader(h0)
    await store.putHeader(h1)

    const tip = await store.getTip()
    expect(tip).not.toBeNull()
    expect(tip!.height).toBe(5)
  })

  it('getHeaderCount', async () => {
    const store = new MemHeaderStore()
    expect(await store.getHeaderCount()).toBe(0)

    const h0 = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    await store.putHeader(h0)
    expect(await store.getHeaderCount()).toBe(1)

    const h1 = buildTestHeader(1, h0.hash, makeHash(0x22))
    await store.putHeader(h1)
    expect(await store.getHeaderCount()).toBe(2)
  })

  it('rejects duplicate header', async () => {
    const store = new MemHeaderStore()
    const h = buildTestHeader(0, makeHash(0x00), makeHash(0x11))

    await store.putHeader(h)
    await expectSpvErrorAsync(store.putHeader(h), 'ERR_DUPLICATE_HEADER')
  })

  it('getHeader returns a deep copy', async () => {
    const store = new MemHeaderStore()
    const h = buildTestHeader(0, makeHash(0x00), makeHash(0x11))
    await store.putHeader(h)

    const got1 = await store.getHeader(h.hash)
    const got2 = await store.getHeader(h.hash)
    expect(got1).toEqual(got2)
    // Mutating one should not affect the other
    got1!.prevBlock[0] = 0xff
    expect(got2!.prevBlock[0]).not.toBe(0xff)
  })
})
