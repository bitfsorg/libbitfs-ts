// metanet/merkle — Directory Merkle tree (double-SHA256, even padding by duplication)
//
// Identical algorithm to Bitcoin block Merkle tree:
// 1. Compute leaf hashes: leaf[i] = DoubleHash(serialize(child[i]))
// 2. If odd count, duplicate last leaf
// 3. Pair adjacent and hash: parent = DoubleHash(left || right)
// 4. Repeat until one root remains

import { Hash } from '@bsv/sdk'
import type { ChildEntry } from './types.js'
import { serializeChildEntry } from './tlv.js'
import { timingSafeEqual } from '../util.js'

/**
 * Computes SHA256(SHA256(data)), matching Bitcoin's hash function.
 */
export function doubleHash(data: Uint8Array): Uint8Array {
  const first = Hash.sha256(Array.from(data))
  const second = Hash.sha256(first)
  return new Uint8Array(second)
}

/**
 * Computes the Merkle leaf hash for a single ChildEntry.
 * leaf_hash = DoubleHash(serialize(entry))
 */
export function computeChildLeafHash(entry: ChildEntry): Uint8Array {
  const serialized = serializeChildEntry(entry)
  return doubleHash(serialized)
}

/**
 * Computes the Merkle root from a directory's children list.
 * Returns null for empty children slice.
 *
 * Algorithm (identical to Bitcoin block Merkle tree):
 * 1. Compute leaf hashes: leaf[i] = DoubleHash(serialize(child[i]))
 * 2. If odd count, duplicate last leaf
 * 3. Pair adjacent and hash: parent = DoubleHash(left || right)
 * 4. Repeat until one root remains
 */
export function computeDirectoryMerkleRoot(children: ChildEntry[]): Uint8Array | null {
  if (children.length === 0) return null

  // Compute leaf hashes
  let level: Uint8Array[] = children.map((c) => computeChildLeafHash(c))

  // Build Merkle tree bottom-up
  while (level.length > 1) {
    // Pad if odd by duplicating last element
    if (level.length % 2 !== 0) {
      const dup = new Uint8Array(32)
      dup.set(level[level.length - 1])
      level.push(dup)
    }

    const nextLevel: Uint8Array[] = []
    for (let i = 0; i < level.length; i += 2) {
      const combined = new Uint8Array(64)
      combined.set(level[i], 0)
      combined.set(level[i + 1], 32)
      nextLevel.push(doubleHash(combined))
    }
    level = nextLevel
  }

  return level[0]
}

/**
 * Builds a Merkle proof for a child at the given position index.
 * Returns the sibling hashes needed to recompute the root.
 * For a single child, returns an empty proof array (the leaf IS the root).
 */
export function buildDirectoryMerkleProof(children: ChildEntry[], childIndex: number): Uint8Array[] {
  if (children.length === 0) {
    throw new Error('cannot build proof for empty children')
  }
  if (childIndex < 0 || childIndex >= children.length) {
    throw new Error(`child index ${childIndex} out of range [0, ${children.length})`)
  }

  // Single child: no proof needed (leaf is root)
  if (children.length === 1) {
    return []
  }

  // Compute all leaf hashes
  let level: Uint8Array[] = children.map((c) => computeChildLeafHash(c))

  const proof: Uint8Array[] = []
  let idx = childIndex

  while (level.length > 1) {
    // Pad if odd
    if (level.length % 2 !== 0) {
      const dup = new Uint8Array(32)
      dup.set(level[level.length - 1])
      level.push(dup)
    }

    // Collect sibling
    if (idx % 2 === 0) {
      const sibling = new Uint8Array(32)
      sibling.set(level[idx + 1])
      proof.push(sibling)
    } else {
      const sibling = new Uint8Array(32)
      sibling.set(level[idx - 1])
      proof.push(sibling)
    }

    // Build next level
    const nextLevel: Uint8Array[] = []
    for (let i = 0; i < level.length; i += 2) {
      const combined = new Uint8Array(64)
      combined.set(level[i], 0)
      combined.set(level[i + 1], 32)
      nextLevel.push(doubleHash(combined))
    }
    level = nextLevel
    idx = Math.floor(idx / 2)
  }

  return proof
}

/**
 * Verifies that a ChildEntry belongs to a directory with the given MerkleRoot,
 * using the provided proof path and position index.
 */
export function verifyChildMembership(
  entry: ChildEntry,
  proof: Uint8Array[],
  index: number,
  merkleRoot: Uint8Array,
): boolean {
  if (merkleRoot.length !== 32) return false

  let hash = computeChildLeafHash(entry)

  // Walk the proof path
  if (proof.length === 0 && index === 0) {
    // Single child case: leaf is root
    return timingSafeEqual(hash, merkleRoot)
  }

  for (let i = 0; i < proof.length; i++) {
    if (proof[i].length !== 32) return false
    const combined = new Uint8Array(64)
    if (((index >>> i) & 1) === 0) {
      // Current hash is on the left
      combined.set(hash, 0)
      combined.set(proof[i], 32)
    } else {
      // Current hash is on the right
      combined.set(proof[i], 0)
      combined.set(hash, 32)
    }
    hash = doubleHash(combined)
  }

  return timingSafeEqual(hash, merkleRoot)
}

