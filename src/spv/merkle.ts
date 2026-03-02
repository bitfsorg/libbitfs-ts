// spv/merkle — Bitcoin Merkle tree: double-SHA256, even padding by duplication

import { Hash } from '@bsv/sdk'
import { HASH_SIZE } from './types.js'

/**
 * Computes SHA256(SHA256(data)), matching Bitcoin's hash function.
 */
export function doubleHash(data: Uint8Array): Uint8Array {
  const first = Hash.sha256(Array.from(data))
  const second = Hash.sha256(first)
  return new Uint8Array(second)
}

/**
 * Computes the Merkle root from a transaction hash, its index position in the
 * block, and the proof branch nodes (bottom-up).
 *
 * Algorithm:
 *   hash = txHash
 *   for i, node in proofNodes:
 *       if bit i of index is 0:  hash = DoubleHash(hash || node)
 *       else:                     hash = DoubleHash(node || hash)
 *
 * Returns null if txHash or any proof node is not 32 bytes.
 */
export function computeMerkleRoot(
  txHash: Uint8Array,
  index: number,
  proofNodes: Uint8Array[],
): Uint8Array | null {
  if (txHash.length !== HASH_SIZE) return null

  let hash: Uint8Array = new Uint8Array(HASH_SIZE)
  hash.set(txHash)

  for (let i = 0; i < proofNodes.length; i++) {
    const node = proofNodes[i]
    if (node.length !== HASH_SIZE) return null

    const combined = new Uint8Array(64)
    if (((index >>> i) & 1) === 0) {
      // Current hash is on the left
      combined.set(hash, 0)
      combined.set(node, 32)
    } else {
      // Current hash is on the right
      combined.set(node, 0)
      combined.set(hash, 32)
    }
    hash = doubleHash(combined)
  }

  return hash
}

/**
 * Verifies that a transaction is included in a block by recomputing the Merkle
 * path from TxID + proof nodes and checking against the expected Merkle root.
 *
 * Returns true if the proof is valid, false otherwise.
 * Throws on invalid inputs (null proof, wrong lengths).
 */
export function verifyMerkleProof(
  proof: { txID: Uint8Array; index: number; nodes: Uint8Array[] },
  expectedMerkleRoot: Uint8Array,
): boolean {
  if (proof.txID.length !== HASH_SIZE) {
    throw new Error('spv: TxID must be 32 bytes')
  }
  if (expectedMerkleRoot.length !== HASH_SIZE) {
    throw new Error('spv: expected merkle root must be 32 bytes')
  }

  const computedRoot = computeMerkleRoot(proof.txID, proof.index, proof.nodes)
  if (computedRoot === null) {
    return false
  }

  return bytesEqual(computedRoot, expectedMerkleRoot)
}

/**
 * Builds a full Merkle tree from a list of transaction hashes.
 * Returns the final root level (single-element array containing the root hash).
 * Returns null for empty input.
 *
 * Each level is padded by duplicating the last element if odd.
 */
export function buildMerkleTree(txHashes: Uint8Array[]): Uint8Array[] | null {
  if (txHashes.length === 0) return null

  // Copy leaves
  let level: Uint8Array[] = txHashes.map((h) => {
    const copy = new Uint8Array(HASH_SIZE)
    copy.set(h)
    return copy
  })

  // Build tree levels until we reach the root
  while (level.length > 1) {
    // If odd number, duplicate last element
    if (level.length % 2 !== 0) {
      const dup = new Uint8Array(HASH_SIZE)
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

  return level
}

/**
 * Computes the Merkle root from a list of transaction IDs.
 * This is used when you have all transactions in a block and want to verify
 * the block header's Merkle root.
 */
export function computeMerkleRootFromTxList(txIDs: Uint8Array[]): Uint8Array | null {
  const tree = buildMerkleTree(txIDs)
  if (tree === null) return null
  return tree[0]
}

/** Compares two Uint8Arrays for byte-level equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}
