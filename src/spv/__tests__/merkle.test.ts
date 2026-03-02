import { describe, it, expect } from 'vitest'
import { Hash } from '@bsv/sdk'
import {
  doubleHash,
  computeMerkleRoot,
  verifyMerkleProof,
  buildMerkleTree,
  computeMerkleRootFromTxList,
} from '../merkle.js'
import { SpvError } from '../errors.js'
import { HASH_SIZE } from '../types.js'
import type { MerkleProof, StoredTx, BlockHeader } from '../types.js'
import { Network } from '../types.js'
import { MemHeaderStore, MemTxStore } from '../store.js'
import { computeHeaderHash, verifyPoW } from '../header.js'
import { verifyTransaction, verifyTransactionWithNetwork } from '../verify.js'

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
 * Builds a valid Merkle proof for a 2-tx block where txHash is at index 0.
 */
function buildTestProof(txHash: Uint8Array): { proof: MerkleProof; merkleRoot: Uint8Array } {
  const otherTx = makeTxHash(0x99)
  const combined = new Uint8Array(64)
  combined.set(txHash, 0)
  combined.set(otherTx, 32)
  const merkleRoot = doubleHash(combined)

  const proof: MerkleProof = {
    txID: txHash,
    index: 0,
    nodes: [otherTx],
    blockHash: makeHash(0xbb),
  }

  return { proof, merkleRoot }
}

/** Builds a test header with mined nonce (regtest difficulty). */
function buildTestHeader(height: number, prevBlock: Uint8Array, merkleRoot: Uint8Array): BlockHeader {
  const h: BlockHeader = {
    version: 1,
    prevBlock,
    merkleRoot,
    timestamp: 1700000000,
    bits: 0x207fffff,
    nonce: 0,
    height,
    hash: new Uint8Array(0),
  }
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

// --- DoubleHash tests ---

describe('doubleHash', () => {
  it('produces 32 bytes for various inputs', () => {
    const cases = [
      new Uint8Array(0),
      new Uint8Array([0x42]),
      new Uint8Array(32).fill(0xaa),
      new Uint8Array(1000).fill(0xff),
    ]

    for (const data of cases) {
      const result = doubleHash(data)
      expect(result.length).toBe(32)

      // Verify manually: SHA256(SHA256(data))
      const first = new Uint8Array(Hash.sha256(Array.from(data)))
      const second = new Uint8Array(Hash.sha256(Array.from(first)))
      expect(result).toEqual(second)
    }
  })

  it('is deterministic', () => {
    const data = new TextEncoder().encode('bitcoin transaction data')
    const h1 = doubleHash(data)
    const h2 = doubleHash(data)
    expect(h1).toEqual(h2)
  })

  it('different inputs produce different hashes', () => {
    const h1 = doubleHash(new TextEncoder().encode('data1'))
    const h2 = doubleHash(new TextEncoder().encode('data2'))
    expect(h1).not.toEqual(h2)
  })
})

// --- ComputeMerkleRoot tests ---

describe('computeMerkleRoot', () => {
  it('single proof node at index 0 (left)', () => {
    const txHash = makeTxHash(0x01)
    const sibling = makeTxHash(0x02)

    const root = computeMerkleRoot(txHash, 0, [sibling])
    expect(root).not.toBeNull()
    expect(root!.length).toBe(32)

    // Manual computation: hash is on the left
    const combined = new Uint8Array(64)
    combined.set(txHash, 0)
    combined.set(sibling, 32)
    const expected = doubleHash(combined)
    expect(root).toEqual(expected)
  })

  it('single proof node at index 1 (right)', () => {
    const txHash = makeTxHash(0x01)
    const sibling = makeTxHash(0x02)

    const root = computeMerkleRoot(txHash, 1, [sibling])
    expect(root).not.toBeNull()
    expect(root!.length).toBe(32)

    // Manual computation: hash is on the right
    const combined = new Uint8Array(64)
    combined.set(sibling, 0)
    combined.set(txHash, 32)
    const expected = doubleHash(combined)
    expect(root).toEqual(expected)
  })

  it('two-level tree: verify proof for tx at index 2', () => {
    // Build a 4-tx tree
    const tx0 = makeTxHash(0x10)
    const tx1 = makeTxHash(0x11)
    const tx2 = makeTxHash(0x12) // target
    const tx3 = makeTxHash(0x13)

    // Level 0 pairs
    const pair01 = new Uint8Array(64)
    pair01.set(tx0, 0)
    pair01.set(tx1, 32)
    const h01 = doubleHash(pair01)

    const pair23 = new Uint8Array(64)
    pair23.set(tx2, 0)
    pair23.set(tx3, 32)
    const h23 = doubleHash(pair23)

    // Root = hash(h01, h23)
    const rootPair = new Uint8Array(64)
    rootPair.set(h01, 0)
    rootPair.set(h23, 32)
    const expectedRoot = doubleHash(rootPair)

    // Proof for tx2 (index 2 = binary 10):
    // Level 0: bit 0 = 0, tx2 is left, sibling = tx3
    // Level 1: bit 1 = 1, h23 is right, sibling = h01
    const proofNodes = [tx3, h01]
    const computedRoot = computeMerkleRoot(tx2, 2, proofNodes)

    expect(computedRoot).toEqual(expectedRoot)
  })

  it('returns null for invalid txHash length', () => {
    const result = computeMerkleRoot(new Uint8Array([0x01]), 0, [makeHash(0xaa)])
    expect(result).toBeNull()
  })

  it('returns null for invalid proof node length', () => {
    const txHash = makeHash(0x01)
    const result = computeMerkleRoot(txHash, 0, [new Uint8Array([0x01, 0x02])])
    expect(result).toBeNull()
  })

  it('empty proof nodes returns txHash itself', () => {
    const txHash = makeHash(0x01)
    const result = computeMerkleRoot(txHash, 0, [])
    expect(result).toEqual(txHash)
  })
})

// --- BuildMerkleTree tests ---

describe('buildMerkleTree', () => {
  it('single tx: root is the tx itself', () => {
    const txHash = makeTxHash(0x01)
    const tree = buildMerkleTree([txHash])
    expect(tree).not.toBeNull()
    expect(tree!.length).toBe(1)
    expect(tree![0]).toEqual(txHash)
  })

  it('two txs: root = hash(tx0 || tx1)', () => {
    const tx0 = makeTxHash(0x01)
    const tx1 = makeTxHash(0x02)

    const tree = buildMerkleTree([tx0, tx1])
    expect(tree).not.toBeNull()
    expect(tree!.length).toBe(1)

    const combined = new Uint8Array(64)
    combined.set(tx0, 0)
    combined.set(tx1, 32)
    const expected = doubleHash(combined)
    expect(tree![0]).toEqual(expected)
  })

  it('four txs: correct root', () => {
    const txs = [0, 1, 2, 3].map((i) => makeTxHash(i))
    const tree = buildMerkleTree(txs)
    expect(tree).not.toBeNull()
    expect(tree!.length).toBe(1)

    // Compute expected root manually
    const p01 = new Uint8Array(64)
    p01.set(txs[0], 0)
    p01.set(txs[1], 32)
    const h01 = doubleHash(p01)

    const p23 = new Uint8Array(64)
    p23.set(txs[2], 0)
    p23.set(txs[3], 32)
    const h23 = doubleHash(p23)

    const rootPair = new Uint8Array(64)
    rootPair.set(h01, 0)
    rootPair.set(h23, 32)
    const expected = doubleHash(rootPair)

    expect(tree![0]).toEqual(expected)
  })

  it('three txs: odd padding by duplicating last', () => {
    const txs = [10, 11, 12].map((i) => makeTxHash(i))
    const tree = buildMerkleTree(txs)
    expect(tree).not.toBeNull()
    expect(tree!.length).toBe(1)

    // With 3 txs, the 4th is a duplicate of the 3rd
    const p01 = new Uint8Array(64)
    p01.set(txs[0], 0)
    p01.set(txs[1], 32)
    const h01 = doubleHash(p01)

    const p23 = new Uint8Array(64)
    p23.set(txs[2], 0)
    p23.set(txs[2], 32) // duplicated
    const h23 = doubleHash(p23)

    const rootPair = new Uint8Array(64)
    rootPair.set(h01, 0)
    rootPair.set(h23, 32)
    const expected = doubleHash(rootPair)

    expect(tree![0]).toEqual(expected)
  })

  it('empty input returns null', () => {
    expect(buildMerkleTree([])).toBeNull()
  })
})

describe('computeMerkleRootFromTxList', () => {
  it('matches buildMerkleTree result', () => {
    const txs = [0, 1, 2, 3].map((i) => makeTxHash(i))

    const root = computeMerkleRootFromTxList(txs)
    expect(root).not.toBeNull()
    expect(root!.length).toBe(32)

    const tree = buildMerkleTree(txs)
    expect(root).toEqual(tree![0])
  })

  it('empty input returns null', () => {
    expect(computeMerkleRootFromTxList([])).toBeNull()
  })
})

// --- VerifyMerkleProof tests ---

describe('verifyMerkleProof', () => {
  it('valid proof passes', () => {
    const txHash = makeTxHash(0x42)
    const { proof, merkleRoot } = buildTestProof(txHash)
    expect(verifyMerkleProof(proof, merkleRoot)).toBe(true)
  })

  it('wrong root fails', () => {
    const txHash = makeTxHash(0x42)
    const { proof } = buildTestProof(txHash)
    const wrongRoot = makeHash(0xff)
    expect(verifyMerkleProof(proof, wrongRoot)).toBe(false)
  })

  it('invalid TxID length throws', () => {
    const proof = {
      txID: new Uint8Array([0x01, 0x02]),
      index: 0,
      nodes: [makeHash(0xaa)],
    }
    expect(() => verifyMerkleProof(proof, makeHash(0x00))).toThrow('TxID must be 32 bytes')
  })

  it('invalid expected root length throws', () => {
    const proof = {
      txID: makeHash(0x01),
      index: 0,
      nodes: [makeHash(0xaa)],
    }
    expect(() => verifyMerkleProof(proof, new Uint8Array([0x01]))).toThrow('expected merkle root must be 32 bytes')
  })

  it('single-tx block: txHash is the merkle root', () => {
    const txHash = makeHash(0x42)
    const proof = {
      txID: txHash,
      index: 0,
      nodes: [] as Uint8Array[],
    }
    expect(verifyMerkleProof(proof, txHash)).toBe(true)
  })

  it('single-tx block with wrong root fails', () => {
    const txHash = makeHash(0x42)
    const proof = {
      txID: txHash,
      index: 0,
      nodes: [] as Uint8Array[],
    }
    expect(verifyMerkleProof(proof, makeHash(0xff))).toBe(false)
  })

  it('4-tx tree: verify proof for tx[2]', () => {
    const txs = [0x10, 0x11, 0x12, 0x13].map((i) => makeTxHash(i))

    const p01 = new Uint8Array(64)
    p01.set(txs[0], 0)
    p01.set(txs[1], 32)
    const h01 = doubleHash(p01)

    const p23 = new Uint8Array(64)
    p23.set(txs[2], 0)
    p23.set(txs[3], 32)
    const h23 = doubleHash(p23)

    const rootPair = new Uint8Array(64)
    rootPair.set(h01, 0)
    rootPair.set(h23, 32)
    const expectedRoot = doubleHash(rootPair)

    const proof = {
      txID: txs[2],
      index: 2,
      nodes: [txs[3], h01],
    }
    expect(verifyMerkleProof(proof, expectedRoot)).toBe(true)
  })
})

// --- MemTxStore tests ---

describe('MemTxStore', () => {
  const txID = makeTxHash(0x42)
  const storedTx: StoredTx = {
    txID,
    rawTx: new Uint8Array([0x01, 0x02, 0x03]),
    blockHash: makeHash(0xbb),
    blockHeight: 100,
  }

  it('putTx + getTx round-trip', async () => {
    const store = new MemTxStore()
    await store.putTx(storedTx)

    const got = await store.getTx(txID)
    expect(got).not.toBeNull()
    expect(got!.txID).toEqual(txID)
    expect(got!.blockHeight).toBe(100)
  })

  it('getTx returns null for unknown txID', async () => {
    const store = new MemTxStore()
    const got = await store.getTx(makeHash(0xff))
    expect(got).toBeNull()
  })

  it('rejects duplicate tx', async () => {
    const store = new MemTxStore()
    await store.putTx(storedTx)
    await expectSpvErrorAsync(store.putTx(storedTx), 'ERR_DUPLICATE_TX')
  })

  it('deleteTx removes the tx', async () => {
    const store = new MemTxStore()
    await store.putTx(storedTx)

    await store.deleteTx(txID)
    const got = await store.getTx(txID)
    expect(got).toBeNull()
  })

  it('deleteTx throws for unknown tx', async () => {
    const store = new MemTxStore()
    await expectSpvErrorAsync(store.deleteTx(makeHash(0xff)), 'ERR_TX_NOT_FOUND')
  })

  it('listTxs returns all stored txs', async () => {
    const store = new MemTxStore()
    await store.putTx(storedTx)

    const tx2ID = makeTxHash(0x43)
    const storedTx2: StoredTx = {
      txID: tx2ID,
      rawTx: new Uint8Array([0x04, 0x05]),
      blockHash: makeHash(0xcc),
      blockHeight: 101,
    }
    await store.putTx(storedTx2)

    const all = await store.listTxs()
    expect(all.length).toBe(2)
  })

  it('rejects invalid TxID length on put', async () => {
    const store = new MemTxStore()
    const bad: StoredTx = {
      txID: new Uint8Array([0x01]),
      rawTx: new Uint8Array(0),
      blockHash: makeHash(0xbb),
      blockHeight: 0,
    }
    await expectSpvErrorAsync(store.putTx(bad), 'ERR_INVALID_TX_ID')
  })
})

// --- VerifyTransaction tests ---

describe('verifyTransaction', () => {
  it('valid transaction verifies', async () => {
    const txHash = makeTxHash(0x42)
    const { proof, merkleRoot } = buildTestProof(txHash)

    // Build a header with the correct merkle root and mine it
    const header = buildTestHeader(100, makeHash(0x00), merkleRoot)
    proof.blockHash = header.hash

    const store = new MemHeaderStore()
    await store.putHeader(header)

    const tx: StoredTx = {
      txID: txHash,
      rawTx: new Uint8Array(0),
      blockHash: header.hash,
      blockHeight: 100,
      merkleProof: proof,
    }

    await expect(verifyTransaction(tx, store)).resolves.toBeUndefined()
  })

  it('unconfirmed transaction throws', async () => {
    const store = new MemHeaderStore()
    const tx: StoredTx = {
      txID: makeTxHash(0x42),
      rawTx: new Uint8Array(0),
      blockHash: makeHash(0xbb),
      blockHeight: 0,
      // no merkleProof
    }
    await expectSpvErrorAsync(verifyTransaction(tx, store), 'ERR_UNCONFIRMED')
  })

  it('missing header throws', async () => {
    const txHash = makeTxHash(0x42)
    const { proof } = buildTestProof(txHash)

    const store = new MemHeaderStore()
    const tx: StoredTx = {
      txID: txHash,
      rawTx: new Uint8Array(0),
      blockHash: proof.blockHash,
      blockHeight: 100,
      merkleProof: proof,
    }

    await expectSpvErrorAsync(verifyTransaction(tx, store), 'ERR_HEADER_NOT_FOUND')
  })

  it('mismatched proof TxID throws', async () => {
    const txHash = makeTxHash(0x42)
    const { proof, merkleRoot } = buildTestProof(txHash)

    const header = buildTestHeader(100, makeHash(0x00), merkleRoot)
    proof.blockHash = header.hash

    const store = new MemHeaderStore()
    await store.putHeader(header)

    const tx: StoredTx = {
      txID: makeTxHash(0x99), // different from proof.txID
      rawTx: new Uint8Array(0),
      blockHash: header.hash,
      blockHeight: 100,
      merkleProof: proof,
    }

    await expectSpvErrorAsync(verifyTransaction(tx, store), 'ERR_MERKLE_PROOF_INVALID')
  })

  it('invalid TxID length throws', async () => {
    const store = new MemHeaderStore()
    const tx: StoredTx = {
      txID: new Uint8Array([0x01]),
      rawTx: new Uint8Array(0),
      blockHash: makeHash(0xbb),
      blockHeight: 0,
    }
    await expectSpvErrorAsync(verifyTransaction(tx, store), 'ERR_INVALID_TX_ID')
  })
})

describe('verifyTransactionWithNetwork', () => {
  it('valid regtest transaction verifies', async () => {
    const txHash = makeTxHash(0x42)
    const { proof, merkleRoot } = buildTestProof(txHash)

    const header = buildTestHeader(100, makeHash(0x00), merkleRoot)
    proof.blockHash = header.hash

    const store = new MemHeaderStore()
    await store.putHeader(header)

    const tx: StoredTx = {
      txID: txHash,
      rawTx: new Uint8Array(0),
      blockHash: header.hash,
      blockHeight: 100,
      merkleProof: proof,
    }

    await expect(verifyTransactionWithNetwork(tx, store, Network.Regtest)).resolves.toBeUndefined()
  })

  it('regtest header fails mainnet verification', async () => {
    const txHash = makeTxHash(0x42)
    const { proof, merkleRoot } = buildTestProof(txHash)

    const header = buildTestHeader(100, makeHash(0x00), merkleRoot)
    proof.blockHash = header.hash

    const store = new MemHeaderStore()
    await store.putHeader(header)

    const tx: StoredTx = {
      txID: txHash,
      rawTx: new Uint8Array(0),
      blockHash: header.hash,
      blockHeight: 100,
      merkleProof: proof,
    }

    // Regtest bits 0x207fffff is too easy for mainnet
    await expectSpvErrorAsync(
      verifyTransactionWithNetwork(tx, store, Network.Mainnet),
      'ERR_DIFFICULTY_TOO_LOW',
    )
  })
})
