import { describe, it, expect } from 'vitest'
import {
  doubleHash,
  computeChildLeafHash,
  computeDirectoryMerkleRoot,
  buildDirectoryMerkleProof,
  verifyChildMembership,
} from '../merkle.js'
import { NodeType } from '../types.js'
import type { ChildEntry } from '../types.js'

/** Creates a test pubkey filled with a byte value. */
function testPubKey(fill: number): Uint8Array {
  const pk = new Uint8Array(33)
  pk[0] = 0x02
  for (let i = 1; i < 33; i++) pk[i] = fill
  return pk
}

function makeEntry(name: string, fill: number): ChildEntry {
  return {
    index: fill,
    name,
    type: NodeType.File,
    pubKey: testPubKey(fill),
    hardened: false,
  }
}

describe('doubleHash', () => {
  it('returns 32 bytes', () => {
    const hash = doubleHash(new Uint8Array([1, 2, 3]))
    expect(hash).toHaveLength(32)
  })

  it('produces deterministic output', () => {
    const data = new Uint8Array([0xaa, 0xbb, 0xcc])
    const h1 = doubleHash(data)
    const h2 = doubleHash(data)
    expect(h1).toEqual(h2)
  })

  it('different inputs produce different hashes', () => {
    const h1 = doubleHash(new Uint8Array([1]))
    const h2 = doubleHash(new Uint8Array([2]))
    expect(h1).not.toEqual(h2)
  })
})

describe('computeDirectoryMerkleRoot', () => {
  it('returns null for empty children', () => {
    expect(computeDirectoryMerkleRoot([])).toBeNull()
  })

  it('returns leaf hash for single child', () => {
    const entry = makeEntry('file.txt', 1)
    const root = computeDirectoryMerkleRoot([entry])
    const leafHash = computeChildLeafHash(entry)
    expect(root).toEqual(leafHash)
  })

  it('returns 32 bytes for two children', () => {
    const entries = [makeEntry('a', 1), makeEntry('b', 2)]
    const root = computeDirectoryMerkleRoot(entries)
    expect(root).not.toBeNull()
    expect(root!).toHaveLength(32)
  })

  it('produces different root when children change', () => {
    const entries1 = [makeEntry('a', 1), makeEntry('b', 2)]
    const entries2 = [makeEntry('a', 1), makeEntry('c', 3)]
    const root1 = computeDirectoryMerkleRoot(entries1)
    const root2 = computeDirectoryMerkleRoot(entries2)
    expect(root1).not.toEqual(root2)
  })

  it('handles odd number of children (duplication padding)', () => {
    const entries = [makeEntry('a', 1), makeEntry('b', 2), makeEntry('c', 3)]
    const root = computeDirectoryMerkleRoot(entries)
    expect(root).not.toBeNull()
    expect(root!).toHaveLength(32)
  })

  it('handles 4 children (even at all levels)', () => {
    const entries = [makeEntry('a', 1), makeEntry('b', 2), makeEntry('c', 3), makeEntry('d', 4)]
    const root = computeDirectoryMerkleRoot(entries)
    expect(root).not.toBeNull()
    expect(root!).toHaveLength(32)
  })

  it('handles 5 children', () => {
    const entries = [
      makeEntry('a', 1),
      makeEntry('b', 2),
      makeEntry('c', 3),
      makeEntry('d', 4),
      makeEntry('e', 5),
    ]
    const root = computeDirectoryMerkleRoot(entries)
    expect(root).not.toBeNull()
    expect(root!).toHaveLength(32)
  })
})

describe('buildDirectoryMerkleProof', () => {
  it('returns empty proof for single child', () => {
    const entries = [makeEntry('only', 1)]
    const proof = buildDirectoryMerkleProof(entries, 0)
    expect(proof).toHaveLength(0)
  })

  it('returns single-level proof for two children', () => {
    const entries = [makeEntry('a', 1), makeEntry('b', 2)]
    const proof0 = buildDirectoryMerkleProof(entries, 0)
    expect(proof0).toHaveLength(1)

    const proof1 = buildDirectoryMerkleProof(entries, 1)
    expect(proof1).toHaveLength(1)
  })

  it('throws for empty children', () => {
    expect(() => buildDirectoryMerkleProof([], 0)).toThrow('empty')
  })

  it('throws for out-of-range index', () => {
    const entries = [makeEntry('a', 1)]
    expect(() => buildDirectoryMerkleProof(entries, 1)).toThrow('out of range')
    expect(() => buildDirectoryMerkleProof(entries, -1)).toThrow('out of range')
  })

  it('proof length increases logarithmically', () => {
    const entries8 = Array.from({ length: 8 }, (_, i) => makeEntry(`f${i}`, i))
    const proof = buildDirectoryMerkleProof(entries8, 3)
    expect(proof).toHaveLength(3) // log2(8) = 3
  })
})

describe('verifyChildMembership', () => {
  it('verifies single child (no proof)', () => {
    const entries = [makeEntry('only', 1)]
    const root = computeDirectoryMerkleRoot(entries)!
    expect(verifyChildMembership(entries[0], [], 0, root)).toBe(true)
  })

  it('verifies first child of two', () => {
    const entries = [makeEntry('a', 1), makeEntry('b', 2)]
    const root = computeDirectoryMerkleRoot(entries)!
    const proof = buildDirectoryMerkleProof(entries, 0)
    expect(verifyChildMembership(entries[0], proof, 0, root)).toBe(true)
  })

  it('verifies second child of two', () => {
    const entries = [makeEntry('a', 1), makeEntry('b', 2)]
    const root = computeDirectoryMerkleRoot(entries)!
    const proof = buildDirectoryMerkleProof(entries, 1)
    expect(verifyChildMembership(entries[1], proof, 1, root)).toBe(true)
  })

  it('verifies all children in larger tree', () => {
    const entries = Array.from({ length: 7 }, (_, i) => makeEntry(`f${i}`, i))
    const root = computeDirectoryMerkleRoot(entries)!

    for (let i = 0; i < entries.length; i++) {
      const proof = buildDirectoryMerkleProof(entries, i)
      expect(verifyChildMembership(entries[i], proof, i, root)).toBe(true)
    }
  })

  it('rejects tampered entry', () => {
    const entries = [makeEntry('a', 1), makeEntry('b', 2)]
    const root = computeDirectoryMerkleRoot(entries)!
    const proof = buildDirectoryMerkleProof(entries, 0)

    // Tamper with the entry
    const tampered = { ...entries[0], name: 'tampered' }
    expect(verifyChildMembership(tampered, proof, 0, root)).toBe(false)
  })

  it('rejects wrong index', () => {
    const entries = [makeEntry('a', 1), makeEntry('b', 2)]
    const root = computeDirectoryMerkleRoot(entries)!
    const proof = buildDirectoryMerkleProof(entries, 0)

    // Use proof for index 0 but claim index 1
    expect(verifyChildMembership(entries[0], proof, 1, root)).toBe(false)
  })

  it('rejects tampered proof', () => {
    const entries = [makeEntry('a', 1), makeEntry('b', 2), makeEntry('c', 3)]
    const root = computeDirectoryMerkleRoot(entries)!
    const proof = buildDirectoryMerkleProof(entries, 0)

    // Tamper with a proof node
    proof[0][0] ^= 0xff
    expect(verifyChildMembership(entries[0], proof, 0, root)).toBe(false)
  })

  it('rejects tampered merkle root', () => {
    const entries = [makeEntry('a', 1), makeEntry('b', 2)]
    const root = computeDirectoryMerkleRoot(entries)!
    const proof = buildDirectoryMerkleProof(entries, 0)

    const fakeRoot = new Uint8Array(32).fill(0xff)
    expect(verifyChildMembership(entries[0], proof, 0, fakeRoot)).toBe(false)
  })

  it('rejects invalid merkle root length', () => {
    const entries = [makeEntry('a', 1)]
    const proof = buildDirectoryMerkleProof(entries, 0)
    expect(verifyChildMembership(entries[0], proof, 0, new Uint8Array(16))).toBe(false)
  })
})
