// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import type { BlockchainService, MerkleProofData, TxStatus } from './types.js'
import { RPCClient, hexToBytes, reverseBytes, bytesToHex, doubleHash } from './rpc.js'
import { sha256 } from '@noble/hashes/sha256'
import { timingSafeEqual } from '../util.js'

// ---------------------------------------------------------------------------
// SPV types (local definitions until spv module is implemented)
// ---------------------------------------------------------------------------

/**
 * BlockHeader represents a BSV block header (80 bytes serialized).
 * This matches the Go spv.BlockHeader structure.
 */
export interface BlockHeader {
  version: number
  prevBlock: Uint8Array // 32 bytes
  merkleRoot: Uint8Array // 32 bytes
  timestamp: number
  bits: number
  nonce: number
  height: number
  hash: Uint8Array // Computed: double-SHA256 of 80-byte header
}

/**
 * HeaderStore persists block headers for chain verification.
 * This interface mirrors the Go spv.HeaderStore.
 */
export interface HeaderStore {
  putHeader(header: BlockHeader): Promise<void>
  getHeader(blockHash: Uint8Array): Promise<BlockHeader | null>
  getHeaderByHeight(height: number): Promise<BlockHeader | null>
  getTip(): Promise<BlockHeader | null>
  getHeaderCount(): Promise<number>
}

/**
 * MerkleProof for SPV verification.
 * This matches the Go spv.MerkleProof structure.
 */
export interface SPVMerkleProof {
  txID: Uint8Array
  index: number
  nodes: Uint8Array[]
  blockHash: Uint8Array
}

// ---------------------------------------------------------------------------
// Header serialization helpers
// ---------------------------------------------------------------------------

const BLOCK_HEADER_SIZE = 80

/** Deserialize 80 bytes into a BlockHeader. */
function deserializeHeader(data: Uint8Array): BlockHeader {
  if (data.length !== BLOCK_HEADER_SIZE) {
    throw new Error(
      `invalid header: expected ${BLOCK_HEADER_SIZE} bytes, got ${data.length}`,
    )
  }

  const view = new DataView(data.buffer, data.byteOffset, data.length)

  const prevBlock = new Uint8Array(32)
  prevBlock.set(data.slice(4, 36))

  const merkleRoot = new Uint8Array(32)
  merkleRoot.set(data.slice(36, 68))

  return {
    version: view.getInt32(0, true),
    prevBlock,
    merkleRoot,
    timestamp: view.getUint32(68, true),
    bits: view.getUint32(72, true),
    nonce: view.getUint32(76, true),
    height: 0,
    hash: new Uint8Array(0), // Computed separately
  }
}

/** Serialize a BlockHeader to 80 bytes. */
function serializeHeader(h: BlockHeader): Uint8Array {
  const buf = new Uint8Array(BLOCK_HEADER_SIZE)
  const view = new DataView(buf.buffer)

  view.setInt32(0, h.version, true)
  buf.set(h.prevBlock, 4)
  buf.set(h.merkleRoot, 36)
  view.setUint32(68, h.timestamp, true)
  view.setUint32(72, h.bits, true)
  view.setUint32(76, h.nonce, true)

  return buf
}

/** Compute the double-SHA256 hash of a block header. */
function computeHeaderHash(h: BlockHeader): Uint8Array {
  const raw = serializeHeader(h)
  return doubleHash(raw)
}

/** Simple Merkle proof verification. */
function computeMerkleRoot(
  txHash: Uint8Array,
  index: number,
  branches: Uint8Array[],
): Uint8Array {
  let current = txHash
  let idx = index

  for (const branch of branches) {
    const combined = new Uint8Array(64)
    if (idx & 1) {
      combined.set(branch, 0)
      combined.set(current, 32)
    } else {
      combined.set(current, 0)
      combined.set(branch, 32)
    }
    current = sha256(sha256(combined))
    idx >>>= 1
  }

  return current
}

// ---------------------------------------------------------------------------
// VerifyResult
// ---------------------------------------------------------------------------

/** Result of an SPV verification. */
export interface VerifyResult {
  confirmed: boolean
  blockHash: string
  blockHeight: number
}

// ---------------------------------------------------------------------------
// SPVClient
// ---------------------------------------------------------------------------

/**
 * SPVClient bridges the network layer with SPV verification.
 * It fetches headers via RPC and verifies transactions using Merkle proofs.
 */
export class SPVClient {
  private readonly chain: BlockchainService
  private readonly headers: HeaderStore

  /**
   * Optional function to fetch block hash by height.
   * Automatically wired when chain is an RPCClient.
   * Can be set manually for testing.
   */
  getBlockHash: ((height: number) => Promise<string>) | null = null

  constructor(chain: BlockchainService, headerStore: HeaderStore) {
    this.chain = chain
    this.headers = headerStore

    // If chain is an RPCClient, wire up getBlockHash via RPC.
    if (chain instanceof RPCClient) {
      this.getBlockHash = (height: number) =>
        (chain as RPCClient).getBlockHash(height)
    }
  }

  /**
   * Perform SPV verification of a transaction:
   *  1. Check confirmation status
   *  2. For confirmed tx: fetch Merkle proof, verify against stored header
   */
  async verifyTx(txid: string): Promise<VerifyResult> {
    const status = await this.chain.getTxStatus(txid)

    if (!status.confirmed) {
      return { confirmed: false, blockHash: '', blockHeight: 0 }
    }

    // Ensure we have the block header.
    // Block hash from RPC is display hex (big-endian); convert to internal
    // byte order for header store lookup.
    let blockHashDisplay: Uint8Array
    try {
      blockHashDisplay = hexToBytes(status.blockHash)
    } catch {
      throw new Error(`network: invalid block hash: ${status.blockHash}`)
    }
    const blockHashInternal = reverseBytes(blockHashDisplay)

    let header = await this.headers.getHeader(blockHashInternal)
    if (!header) {
      // Header not in store - fetch and store it.
      let rawHeader: Uint8Array
      try {
        rawHeader = await this.chain.getBlockHeader(status.blockHash)
      } catch (err) {
        throw new Error(
          `network: fetch block header: ${err instanceof Error ? err.message : String(err)}`,
        )
      }

      header = deserializeHeader(rawHeader)
      header.height = status.blockHeight
      header.hash = computeHeaderHash(header)
      await this.headers.putHeader(header)
    }

    // Fetch and verify Merkle proof.
    let proof: MerkleProofData
    try {
      proof = await this.chain.getMerkleProof(txid)
    } catch (err) {
      throw new Error(
        `network: fetch merkle proof: ${err instanceof Error ? err.message : String(err)}`,
      )
    }

    let txidDisplayBytes: Uint8Array
    try {
      txidDisplayBytes = hexToBytes(proof.txid)
    } catch {
      throw new Error(`network: invalid txid: ${proof.txid}`)
    }
    // Convert display txid to internal byte order for Merkle verification.
    const txidInternal = reverseBytes(txidDisplayBytes)

    // Single-tx block: txHash IS the Merkle root, no branches needed.
    if (proof.branches.length === 0 && proof.index === 0) {
      if (!timingSafeEqual(txidInternal, header.merkleRoot)) {
        throw new Error(
          `network: merkle proof verification failed for tx ${txid}`,
        )
      }
    } else {
      const computedRoot = computeMerkleRoot(
        txidInternal,
        proof.index,
        proof.branches,
      )
      if (!timingSafeEqual(computedRoot, header.merkleRoot)) {
        throw new Error(
          `network: merkle proof verification failed for tx ${txid}`,
        )
      }
    }

    return {
      confirmed: true,
      blockHash: status.blockHash,
      blockHeight: status.blockHeight,
    }
  }

  /**
   * Fetch block headers from the network and store them locally.
   * Syncs from current tip to the latest block.
   */
  async syncHeaders(): Promise<number> {
    if (!this.getBlockHash) {
      throw new Error('network: getBlockHash not configured')
    }

    let bestHeight: number
    try {
      bestHeight = await this.chain.getBestBlockHeight()
    } catch (err) {
      throw new Error(
        `network: get best block height: ${err instanceof Error ? err.message : String(err)}`,
      )
    }

    // Determine local tip.
    let startHeight = 0
    const tip = await this.headers.getTip()
    if (tip) {
      startHeight = tip.height + 1
    }

    let synced = 0
    for (let h = startHeight; h <= bestHeight; h++) {
      let hash: string
      try {
        hash = await this.getBlockHash(h)
      } catch (err) {
        throw new Error(
          `network: get block hash at ${h}: ${err instanceof Error ? err.message : String(err)}`,
        )
      }

      let rawHeader: Uint8Array
      try {
        rawHeader = await this.chain.getBlockHeader(hash)
      } catch (err) {
        throw new Error(
          `network: get header at ${h}: ${err instanceof Error ? err.message : String(err)}`,
        )
      }

      let header: BlockHeader
      try {
        header = deserializeHeader(rawHeader)
      } catch (err) {
        throw new Error(
          `network: deserialize header at ${h}: ${err instanceof Error ? err.message : String(err)}`,
        )
      }
      header.height = h
      header.hash = computeHeaderHash(header)

      // Validate chain continuity.
      if (h === 0) {
        // Genesis block: PrevBlock should be all zeros.
        const zeros = new Uint8Array(32)
        if (!timingSafeEqual(header.prevBlock, zeros)) {
          throw new Error(
            'network: genesis block has non-zero PrevBlock',
          )
        }
      } else {
        const prevHeader = await this.headers.getHeaderByHeight(h - 1)
        if (!prevHeader) {
          throw new Error(
            `network: previous header at ${h - 1} not found`,
          )
        }
        if (!timingSafeEqual(header.prevBlock, prevHeader.hash)) {
          throw new Error(
            `network: chain break at height ${h}: PrevBlock does not match header at ${h - 1}`,
          )
        }
      }

      await this.headers.putHeader(header)
      synced++
    }

    return synced
  }
}

// Export for testing.
export {
  deserializeHeader,
  serializeHeader,
  computeHeaderHash,
  computeMerkleRoot,
}
