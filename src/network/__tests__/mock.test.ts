// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import { describe, it, expect, beforeEach } from 'vitest'
import { MockBlockchainService, MemHeaderStore } from '../mock.js'
import type { UTXO, TxStatus, MerkleProofData } from '../types.js'
import { TxNotFoundError } from '../errors.js'
import type { BlockHeader } from '../spvclient.js'

// ---------------------------------------------------------------------------
// MockBlockchainService
// ---------------------------------------------------------------------------

describe('MockBlockchainService', () => {
  let mock: MockBlockchainService

  beforeEach(() => {
    mock = new MockBlockchainService()
  })

  // --- listUnspent ---

  it('returns empty array for unknown address', async () => {
    const utxos = await mock.listUnspent('unknown-addr')
    expect(utxos).toEqual([])
  })

  it('returns UTXOs after addUTXOs', async () => {
    const utxo: UTXO = {
      txid: 'abc123',
      vout: 0,
      amount: 100000n,
      scriptPubKey: '76a914deadbeef88ac',
      address: '1TestAddr',
      confirmations: 6,
    }
    mock.addUTXOs('1TestAddr', [utxo])

    const result = await mock.listUnspent('1TestAddr')
    expect(result).toHaveLength(1)
    expect(result[0].txid).toBe('abc123')
    expect(result[0].amount).toBe(100000n)
  })

  it('addUTXOs appends to existing UTXOs', async () => {
    const utxo1: UTXO = {
      txid: 'tx1',
      vout: 0,
      amount: 1000n,
      scriptPubKey: 'script1',
      address: 'addr',
      confirmations: 1,
    }
    const utxo2: UTXO = {
      txid: 'tx2',
      vout: 1,
      amount: 2000n,
      scriptPubKey: 'script2',
      address: 'addr',
      confirmations: 2,
    }

    mock.addUTXOs('addr', [utxo1])
    mock.addUTXOs('addr', [utxo2])

    const result = await mock.listUnspent('addr')
    expect(result).toHaveLength(2)
  })

  // --- getUTXO ---

  it('getUTXO returns matching UTXO', async () => {
    const utxo: UTXO = {
      txid: 'findme',
      vout: 3,
      amount: 5000n,
      scriptPubKey: 'hex',
      address: 'addr1',
      confirmations: 10,
    }
    mock.addUTXOs('addr1', [utxo])

    const found = await mock.getUTXO('findme', 3)
    expect(found).not.toBeNull()
    expect(found!.txid).toBe('findme')
    expect(found!.vout).toBe(3)
  })

  it('getUTXO returns null for non-existent UTXO', async () => {
    const found = await mock.getUTXO('nonexistent', 0)
    expect(found).toBeNull()
  })

  // --- broadcastTx ---

  it('broadcastTx stores the raw hex and returns a txid', async () => {
    const txid = await mock.broadcastTx('0100000001abcdef')
    expect(txid).toBeTruthy()
    expect(typeof txid).toBe('string')
    expect(txid.length).toBe(64) // 32 bytes hex

    expect(mock.broadcastedTxs).toHaveLength(1)
    expect(mock.broadcastedTxs[0]).toBe('0100000001abcdef')
  })

  it('broadcastTx returns deterministic txid for same input', async () => {
    const txid1 = await mock.broadcastTx('same-hex')
    const txid2 = await mock.broadcastTx('same-hex')
    expect(txid1).toBe(txid2)
  })

  // --- getRawTx ---

  it('getRawTx returns stored transaction', async () => {
    const raw = new Uint8Array([0x01, 0x00, 0x00, 0x00])
    mock.addTx('tx123', raw)

    const result = await mock.getRawTx('tx123')
    expect(result).toEqual(raw)
  })

  it('getRawTx throws TxNotFoundError for unknown txid', async () => {
    await expect(mock.getRawTx('unknown')).rejects.toThrow(TxNotFoundError)
  })

  // --- getTxStatus ---

  it('getTxStatus returns set status', async () => {
    const status: TxStatus = {
      confirmed: true,
      blockHash: 'blockhash123',
      blockHeight: 100,
      txIndex: 3,
    }
    mock.setTxStatus('tx456', status)

    const result = await mock.getTxStatus('tx456')
    expect(result.confirmed).toBe(true)
    expect(result.blockHash).toBe('blockhash123')
    expect(result.blockHeight).toBe(100)
  })

  it('getTxStatus returns unconfirmed for unknown txid', async () => {
    const result = await mock.getTxStatus('unknown')
    expect(result.confirmed).toBe(false)
    expect(result.blockHash).toBe('')
  })

  // --- getBlockHeader ---

  it('getBlockHeader returns stored header', async () => {
    const header = new Uint8Array(80).fill(0x42)
    mock.addBlockHeader('blockhash', header)

    const result = await mock.getBlockHeader('blockhash')
    expect(result).toEqual(header)
  })

  it('getBlockHeader throws TxNotFoundError for unknown hash', async () => {
    await expect(mock.getBlockHeader('unknown')).rejects.toThrow(
      TxNotFoundError,
    )
  })

  // --- getMerkleProof ---

  it('getMerkleProof returns stored proof', async () => {
    const proof: MerkleProofData = {
      txid: 'tx789',
      blockHash: 'bh789',
      branches: [new Uint8Array(32).fill(0x01)],
      index: 1,
    }
    mock.addMerkleProof('tx789', proof)

    const result = await mock.getMerkleProof('tx789')
    expect(result.txid).toBe('tx789')
    expect(result.index).toBe(1)
    expect(result.branches).toHaveLength(1)
  })

  it('getMerkleProof throws TxNotFoundError for unknown txid', async () => {
    await expect(mock.getMerkleProof('unknown')).rejects.toThrow(
      TxNotFoundError,
    )
  })

  // --- getBestBlockHeight ---

  it('getBestBlockHeight returns configured height', async () => {
    mock.bestBlockHeight = 850000
    const height = await mock.getBestBlockHeight()
    expect(height).toBe(850000)
  })

  it('getBestBlockHeight defaults to 0', async () => {
    const height = await mock.getBestBlockHeight()
    expect(height).toBe(0)
  })

  // --- importAddress ---

  it('importAddress stores the address', async () => {
    await mock.importAddress('1TestAddr')
    expect(mock.importedAddresses.has('1TestAddr')).toBe(true)
  })

  it('importAddress is idempotent', async () => {
    await mock.importAddress('1TestAddr')
    await mock.importAddress('1TestAddr')
    expect(mock.importedAddresses.size).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// MemHeaderStore
// ---------------------------------------------------------------------------

describe('MemHeaderStore', () => {
  let store: MemHeaderStore

  function makeHeader(height: number): BlockHeader {
    return {
      version: 1,
      prevBlock: new Uint8Array(32),
      merkleRoot: new Uint8Array(32),
      timestamp: 1000 + height,
      bits: 0x207fffff,
      nonce: 0,
      height,
      hash: new Uint8Array(32).fill(height + 1),
    }
  }

  beforeEach(() => {
    store = new MemHeaderStore()
  })

  it('putHeader and getHeader round-trip', async () => {
    const h = makeHeader(0)
    await store.putHeader(h)

    const retrieved = await store.getHeader(h.hash)
    expect(retrieved).not.toBeNull()
    expect(retrieved!.height).toBe(0)
    expect(retrieved!.version).toBe(1)
  })

  it('getHeader returns null for unknown hash', async () => {
    const result = await store.getHeader(new Uint8Array(32).fill(0xff))
    expect(result).toBeNull()
  })

  it('getHeaderByHeight returns correct header', async () => {
    const h0 = makeHeader(0)
    const h1 = makeHeader(1)
    await store.putHeader(h0)
    await store.putHeader(h1)

    const result = await store.getHeaderByHeight(1)
    expect(result).not.toBeNull()
    expect(result!.height).toBe(1)
  })

  it('getHeaderByHeight returns null for unknown height', async () => {
    const result = await store.getHeaderByHeight(999)
    expect(result).toBeNull()
  })

  it('getTip returns header with greatest height', async () => {
    const h0 = makeHeader(0)
    const h5 = makeHeader(5)
    const h3 = makeHeader(3)
    await store.putHeader(h0)
    await store.putHeader(h5)
    await store.putHeader(h3)

    const tip = await store.getTip()
    expect(tip).not.toBeNull()
    expect(tip!.height).toBe(5)
  })

  it('getTip returns null for empty store', async () => {
    const tip = await store.getTip()
    expect(tip).toBeNull()
  })

  it('getHeaderCount returns correct count', async () => {
    expect(await store.getHeaderCount()).toBe(0)

    await store.putHeader(makeHeader(0))
    expect(await store.getHeaderCount()).toBe(1)

    await store.putHeader(makeHeader(1))
    expect(await store.getHeaderCount()).toBe(2)
  })

  it('putHeader overwrites existing header at same height', async () => {
    const h1a = makeHeader(5)
    h1a.nonce = 42
    await store.putHeader(h1a)

    const h1b = makeHeader(5)
    h1b.nonce = 99
    h1b.hash = new Uint8Array(32).fill(0xab)
    await store.putHeader(h1b)

    // Count should still be 1 at height 5.
    const byHeight = await store.getHeaderByHeight(5)
    expect(byHeight!.nonce).toBe(99)
  })
})
