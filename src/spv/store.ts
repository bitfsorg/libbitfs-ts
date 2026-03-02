// spv/store — In-memory implementations of HeaderStore and TxStore

import { HASH_SIZE } from './types.js'
import type { BlockHeader, StoredTx, HeaderStore, TxStore } from './types.js'
import { SpvError } from './errors.js'
import { computeHeaderHash } from './header.js'

/** Converts a Uint8Array to a hex string for use as a Map key. */
function hashKey(h: Uint8Array): string {
  // Use hex encoding for deterministic map keys
  let s = ''
  for (let i = 0; i < h.length; i++) {
    s += h[i].toString(16).padStart(2, '0')
  }
  return s
}

/** Deep-copies a BlockHeader, including all Uint8Array fields. */
function copyBlockHeader(h: BlockHeader): BlockHeader {
  return {
    version: h.version,
    prevBlock: new Uint8Array(h.prevBlock),
    merkleRoot: new Uint8Array(h.merkleRoot),
    timestamp: h.timestamp,
    bits: h.bits,
    nonce: h.nonce,
    height: h.height,
    hash: new Uint8Array(h.hash),
  }
}

/**
 * MemHeaderStore is an in-memory implementation of HeaderStore for testing.
 */
export class MemHeaderStore implements HeaderStore {
  private byHash = new Map<string, BlockHeader>()
  private byHeight = new Map<number, BlockHeader>()
  private tipHeight = -1

  async putHeader(header: BlockHeader): Promise<void> {
    // Compute hash if not set
    if (!header.hash || header.hash.length === 0) {
      header.hash = computeHeaderHash(header)
    }

    if (header.hash.length !== HASH_SIZE) {
      throw new SpvError(
        `spv: header hash must be ${HASH_SIZE} bytes`,
        'ERR_INVALID_HEADER',
      )
    }

    const key = hashKey(header.hash)
    if (this.byHash.has(key)) {
      throw new SpvError('spv: duplicate header', 'ERR_DUPLICATE_HEADER')
    }

    this.byHash.set(key, header)
    this.byHeight.set(header.height, header)

    if (this.tipHeight < 0 || header.height > this.tipHeight) {
      this.tipHeight = header.height
    }
  }

  async getHeader(blockHash: Uint8Array): Promise<BlockHeader | null> {
    if (blockHash.length !== HASH_SIZE) {
      throw new SpvError(
        `spv: block hash must be ${HASH_SIZE} bytes`,
        'ERR_INVALID_HEADER',
      )
    }

    const hdr = this.byHash.get(hashKey(blockHash))
    if (!hdr) return null
    return copyBlockHeader(hdr)
  }

  async getHeaderByHeight(height: number): Promise<BlockHeader | null> {
    const hdr = this.byHeight.get(height)
    if (!hdr) return null
    return copyBlockHeader(hdr)
  }

  async getTip(): Promise<BlockHeader | null> {
    if (this.tipHeight < 0) return null
    const hdr = this.byHeight.get(this.tipHeight)
    if (!hdr) return null
    return copyBlockHeader(hdr)
  }

  async getHeaderCount(): Promise<number> {
    return this.byHash.size
  }
}

/**
 * MemTxStore is an in-memory implementation of TxStore for testing.
 */
export class MemTxStore implements TxStore {
  private byTxID = new Map<string, StoredTx>()

  async putTx(tx: StoredTx): Promise<void> {
    if (tx.txID.length !== HASH_SIZE) {
      throw new SpvError(
        `spv: TxID must be ${HASH_SIZE} bytes`,
        'ERR_INVALID_TX_ID',
      )
    }

    const key = hashKey(tx.txID)
    if (this.byTxID.has(key)) {
      throw new SpvError('spv: duplicate transaction', 'ERR_DUPLICATE_TX')
    }

    this.byTxID.set(key, tx)
  }

  async getTx(txID: Uint8Array): Promise<StoredTx | null> {
    if (txID.length !== HASH_SIZE) {
      throw new SpvError(
        `spv: TxID must be ${HASH_SIZE} bytes`,
        'ERR_INVALID_TX_ID',
      )
    }

    const tx = this.byTxID.get(hashKey(txID))
    if (!tx) return null
    return tx
  }

  async deleteTx(txID: Uint8Array): Promise<void> {
    if (txID.length !== HASH_SIZE) {
      throw new SpvError(
        `spv: TxID must be ${HASH_SIZE} bytes`,
        'ERR_INVALID_TX_ID',
      )
    }

    const key = hashKey(txID)
    if (!this.byTxID.has(key)) {
      throw new SpvError('spv: transaction not found', 'ERR_TX_NOT_FOUND')
    }

    this.byTxID.delete(key)
  }

  async listTxs(): Promise<StoredTx[]> {
    return Array.from(this.byTxID.values())
  }
}
