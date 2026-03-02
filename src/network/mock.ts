// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import type {
  BlockchainService,
  UTXO,
  TxStatus,
  MerkleProofData,
} from './types.js'

import { TxNotFoundError } from './errors.js'
import type { BlockHeader, HeaderStore } from './spvclient.js'

// ---------------------------------------------------------------------------
// MockBlockchainService
// ---------------------------------------------------------------------------

/**
 * In-memory mock implementation of BlockchainService for testing.
 * Stores UTXOs and transactions in Maps, and allows direct manipulation.
 */
export class MockBlockchainService implements BlockchainService {
  /** UTXOs indexed by address. */
  readonly utxos = new Map<string, UTXO[]>()

  /** Raw transactions indexed by txid. */
  readonly txs = new Map<string, Uint8Array>()

  /** Transaction status indexed by txid. */
  readonly txStatuses = new Map<string, TxStatus>()

  /** Block headers indexed by block hash (display hex). */
  readonly blockHeaders = new Map<string, Uint8Array>()

  /** Merkle proofs indexed by txid. */
  readonly merkleProofs = new Map<string, MerkleProofData>()

  /** Current best block height. */
  bestBlockHeight = 0

  /** Imported addresses. */
  readonly importedAddresses = new Set<string>()

  /** Broadcast transactions (raw hex). */
  readonly broadcastedTxs: string[] = []

  // -----------------------------------------------------------------------
  // BlockchainService implementation
  // -----------------------------------------------------------------------

  async listUnspent(address: string): Promise<UTXO[]> {
    return this.utxos.get(address) ?? []
  }

  async getUTXO(txid: string, vout: number): Promise<UTXO | null> {
    for (const utxoList of this.utxos.values()) {
      const found = utxoList.find((u) => u.txid === txid && u.vout === vout)
      if (found) return found
    }
    return null
  }

  async broadcastTx(rawTxHex: string): Promise<string> {
    this.broadcastedTxs.push(rawTxHex)
    // Generate a deterministic fake txid from the hex.
    const { sha256 } = await import('@noble/hashes/sha256')
    const bytes = new TextEncoder().encode(rawTxHex)
    const hash = sha256(sha256(bytes))
    // Return as display hex.
    let hex = ''
    for (let i = hash.length - 1; i >= 0; i--) {
      hex += hash[i].toString(16).padStart(2, '0')
    }
    return hex
  }

  async getRawTx(txid: string): Promise<Uint8Array> {
    const raw = this.txs.get(txid)
    if (!raw) {
      throw new TxNotFoundError(txid)
    }
    return raw
  }

  async getTxStatus(txid: string): Promise<TxStatus> {
    const status = this.txStatuses.get(txid)
    if (status) return status
    // Default: unconfirmed
    return { confirmed: false, blockHash: '', blockHeight: 0, txIndex: 0 }
  }

  async getBlockHeader(blockHash: string): Promise<Uint8Array> {
    const header = this.blockHeaders.get(blockHash)
    if (!header) {
      throw new TxNotFoundError(`block ${blockHash}`)
    }
    return header
  }

  async getMerkleProof(txid: string): Promise<MerkleProofData> {
    const proof = this.merkleProofs.get(txid)
    if (!proof) {
      throw new TxNotFoundError(`merkle proof for ${txid}`)
    }
    return proof
  }

  async getBestBlockHeight(): Promise<number> {
    return this.bestBlockHeight
  }

  async importAddress(address: string): Promise<void> {
    this.importedAddresses.add(address)
  }

  // -----------------------------------------------------------------------
  // Convenience methods for test setup
  // -----------------------------------------------------------------------

  /** Add UTXOs for an address. */
  addUTXOs(address: string, utxos: UTXO[]): void {
    const existing = this.utxos.get(address) ?? []
    this.utxos.set(address, [...existing, ...utxos])
  }

  /** Store a raw transaction. */
  addTx(txid: string, raw: Uint8Array): void {
    this.txs.set(txid, raw)
  }

  /** Set transaction status. */
  setTxStatus(txid: string, status: TxStatus): void {
    this.txStatuses.set(txid, status)
  }

  /** Store a block header. */
  addBlockHeader(blockHash: string, header: Uint8Array): void {
    this.blockHeaders.set(blockHash, header)
  }

  /** Store a Merkle proof. */
  addMerkleProof(txid: string, proof: MerkleProofData): void {
    this.merkleProofs.set(txid, proof)
  }
}

// ---------------------------------------------------------------------------
// MemHeaderStore — in-memory HeaderStore for testing
// ---------------------------------------------------------------------------

/**
 * In-memory implementation of HeaderStore for testing.
 * Mirrors Go's spv.MemHeaderStore.
 */
export class MemHeaderStore implements HeaderStore {
  private readonly byHash = new Map<string, BlockHeader>()
  private readonly byHeight = new Map<number, BlockHeader>()

  async putHeader(header: BlockHeader): Promise<void> {
    const hashKey = hashToKey(header.hash)
    this.byHash.set(hashKey, header)
    this.byHeight.set(header.height, header)
  }

  async getHeader(blockHash: Uint8Array): Promise<BlockHeader | null> {
    const hashKey = hashToKey(blockHash)
    return this.byHash.get(hashKey) ?? null
  }

  async getHeaderByHeight(height: number): Promise<BlockHeader | null> {
    return this.byHeight.get(height) ?? null
  }

  async getTip(): Promise<BlockHeader | null> {
    if (this.byHeight.size === 0) return null

    let maxHeight = -1
    let tip: BlockHeader | null = null
    for (const [height, header] of this.byHeight) {
      if (height > maxHeight) {
        maxHeight = height
        tip = header
      }
    }
    return tip
  }

  async getHeaderCount(): Promise<number> {
    return this.byHeight.size
  }
}

/** Convert a Uint8Array hash to a string key for Map lookup. */
function hashToKey(hash: Uint8Array): string {
  let key = ''
  for (let i = 0; i < hash.length; i++) {
    key += hash[i].toString(16).padStart(2, '0')
  }
  return key
}
