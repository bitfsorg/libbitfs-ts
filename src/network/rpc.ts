// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import type {
  BlockchainService,
  UTXO,
  TxStatus,
  MerkleProofData,
  RPCConfig,
} from './types.js'

import {
  ConnectionFailedError,
  AuthFailedError,
  BroadcastRejectedError,
  InvalidResponseError,
  RPCError,
} from './errors.js'

import { sha256 } from '@noble/hashes/sha256'
import { timingSafeEqual } from '../util.js'

// ---------------------------------------------------------------------------
// Internal types for JSON-RPC 1.0
// ---------------------------------------------------------------------------

interface RPCRequest {
  jsonrpc: string
  id: number
  method: string
  params: unknown[]
}

interface RPCResponse {
  id: number
  result: unknown
  error: { code: number; message: string } | null
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Convert a BTC float amount (as returned by the RPC node) to satoshis.
 * Uses Math.round to avoid floating-point truncation.
 */
function btcToSat(btc: number): bigint {
  if (btc <= 0) return 0n
  return BigInt(Math.round(btc * 1e8))
}

/** Decode a hex string to Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new InvalidResponseError(`odd-length hex string: ${hex.length}`)
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.substring(i, i + 2), 16)
    if (Number.isNaN(byte)) {
      throw new InvalidResponseError(`invalid hex character at position ${i}`)
    }
    bytes[i / 2] = byte
  }
  return bytes
}

/** Reverse a Uint8Array (returns a new copy). */
function reverseBytes(data: Uint8Array): Uint8Array {
  const result = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i++) {
    result[data.length - 1 - i] = data[i]
  }
  return result
}

/** Double-SHA256 hash (synchronous, using @noble/hashes). */
function doubleHash(data: Uint8Array): Uint8Array {
  return sha256(sha256(data))
}

/** Read a Bitcoin-style variable-length integer from data at offset. */
function readVarInt(
  data: Uint8Array,
  offset: number,
): { value: number; bytesRead: number } {
  if (offset >= data.length) return { value: 0, bytesRead: 0 }
  const first = data[offset]
  if (first < 0xfd) {
    return { value: first, bytesRead: 1 }
  } else if (first === 0xfd) {
    if (offset + 3 > data.length) return { value: 0, bytesRead: 0 }
    const view = new DataView(data.buffer, data.byteOffset + offset + 1, 2)
    return { value: view.getUint16(0, true), bytesRead: 3 }
  } else if (first === 0xfe) {
    if (offset + 5 > data.length) return { value: 0, bytesRead: 0 }
    const view = new DataView(data.buffer, data.byteOffset + offset + 1, 4)
    return { value: view.getUint32(0, true), bytesRead: 5 }
  } else {
    // 0xff — 8 byte uint64; we cap at Number.MAX_SAFE_INTEGER.
    if (offset + 9 > data.length) return { value: 0, bytesRead: 0 }
    const view = new DataView(data.buffer, data.byteOffset + offset + 1, 8)
    const lo = view.getUint32(0, true)
    const hi = view.getUint32(4, true)
    return { value: hi * 0x100000000 + lo, bytesRead: 9 }
  }
}

// ---------------------------------------------------------------------------
// BIP37 CMerkleBlock parsing
// ---------------------------------------------------------------------------

const MAX_MERKLE_TREE_TXS = 1 << 20

function calcTreeWidth(totalLeaves: number, depth: number): number {
  return (totalLeaves + (1 << depth) - 1) >>> depth
}

interface ParsedMerkleBlock {
  header: Uint8Array
  txIndex: number
  branches: Uint8Array[]
  totalTxs: number
}

/**
 * Parse a BIP37-encoded CMerkleBlock and extract the Merkle branch
 * for the target transaction.
 */
function parseBIP37MerkleBlock(
  data: Uint8Array,
  targetTxID: Uint8Array,
): ParsedMerkleBlock {
  if (data.length < 84) {
    throw new InvalidResponseError(
      `CMerkleBlock too short: ${data.length} bytes`,
    )
  }

  const header = data.slice(0, 80)
  const totalTxsView = new DataView(
    data.buffer,
    data.byteOffset + 80,
    4,
  )
  const totalTxs = totalTxsView.getUint32(0, true)
  let pos = 84

  if (totalTxs === 0) {
    throw new InvalidResponseError('totalTxs is zero')
  }
  if (totalTxs > MAX_MERKLE_TREE_TXS) {
    throw new InvalidResponseError(
      `totalTxs ${totalTxs} exceeds maximum ${MAX_MERKLE_TREE_TXS}`,
    )
  }

  // Read varint: number of hashes.
  const { value: numHashes, bytesRead: hashVarIntBytes } = readVarInt(
    data,
    pos,
  )
  if (hashVarIntBytes === 0) {
    throw new InvalidResponseError('failed to read hash count varint')
  }
  pos += hashVarIntBytes

  // Validate hash count.
  const remainingBytes = data.length - pos
  if (numHashes > remainingBytes / 32) {
    throw new InvalidResponseError(
      `hash count ${numHashes} exceeds available data (${remainingBytes} bytes remaining)`,
    )
  }

  const hashes: Uint8Array[] = []
  for (let i = 0; i < numHashes; i++) {
    if (pos + 32 > data.length) {
      throw new InvalidResponseError(
        `unexpected end of data reading hash ${i}`,
      )
    }
    hashes.push(data.slice(pos, pos + 32))
    pos += 32
  }

  // Read varint: number of flag bytes.
  const { value: numFlagBytes, bytesRead: flagVarIntBytes } = readVarInt(
    data,
    pos,
  )
  if (flagVarIntBytes === 0) {
    throw new InvalidResponseError('failed to read flag bytes count varint')
  }
  pos += flagVarIntBytes

  if (pos + numFlagBytes > data.length) {
    throw new InvalidResponseError('unexpected end of data reading flags')
  }
  const flagBytes = data.slice(pos, pos + numFlagBytes)

  // Traverse the partial Merkle tree.
  const result = traversePartialMerkleTree(
    hashes,
    flagBytes,
    totalTxs,
    targetTxID,
  )

  return {
    header,
    txIndex: result.txIndex,
    branches: result.branches,
    totalTxs,
  }
}

interface TraverseResult {
  txIndex: number
  branches: Uint8Array[]
}

function traversePartialMerkleTree(
  hashes: Uint8Array[],
  flagBytes: Uint8Array,
  totalTxs: number,
  targetTxID: Uint8Array,
): TraverseResult {
  // Compute tree height.
  let height = 0
  while (calcTreeWidth(totalTxs, height) > 1) {
    height++
  }

  let hashIdx = 0
  let bitIdx = 0
  let hashErr: string | null = null

  function getBit(): boolean {
    if (Math.floor(bitIdx / 8) >= flagBytes.length) return false
    const bit =
      (flagBytes[Math.floor(bitIdx / 8)] >> (bitIdx % 8)) & 1
    bitIdx++
    return bit === 1
  }

  function getHash(): Uint8Array {
    if (hashIdx >= hashes.length) {
      hashErr = `merkle hash pool exhausted at index ${hashIdx}`
      return new Uint8Array(32)
    }
    const h = hashes[hashIdx]
    hashIdx++
    return h
  }

  interface NodeResult {
    hash: Uint8Array
    found: boolean
    index: number
    branch: Uint8Array[]
  }

  function doubleHashSync(data: Uint8Array): Uint8Array {
    return sha256(sha256(data))
  }

  function traverse(depth: number, pos: number): NodeResult {
    const flag = getBit()

    if (depth === 0) {
      const h = getHash()
      const isTarget = timingSafeEqual(h, targetTxID)
      return { hash: h, found: isTarget, index: pos, branch: [] }
    }

    if (!flag) {
      const h = getHash()
      return { hash: h, found: false, index: 0, branch: [] }
    }

    const left = traverse(depth - 1, pos * 2)

    let right: NodeResult
    if (pos * 2 + 1 < calcTreeWidth(totalTxs, depth - 1)) {
      right = traverse(depth - 1, pos * 2 + 1)
    } else {
      right = { hash: left.hash, found: false, index: 0, branch: [] }
    }

    const combined = new Uint8Array(64)
    combined.set(left.hash, 0)
    combined.set(right.hash, 32)
    const parentHash = doubleHashSync(combined)

    const result: NodeResult = {
      hash: parentHash,
      found: false,
      index: 0,
      branch: [],
    }

    if (left.found) {
      result.found = true
      result.index = left.index
      result.branch = [...left.branch, right.hash]
    } else if (right.found) {
      result.found = true
      result.index = right.index
      result.branch = [...right.branch, left.hash]
    }

    return result
  }

  const result = traverse(height, 0)

  if (hashErr) {
    throw new InvalidResponseError(hashErr)
  }
  if (!result.found) {
    throw new InvalidResponseError(
      'target tx not found in partial merkle tree',
    )
  }

  return { txIndex: result.index, branches: result.branch }
}

// ---------------------------------------------------------------------------
// RPCClient
// ---------------------------------------------------------------------------

/**
 * JSON-RPC 1.0 client for communicating with BSV nodes.
 * Implements BlockchainService via JSON-RPC calls.
 */
export class RPCClient implements BlockchainService {
  private readonly url: string
  private readonly user: string
  private readonly pass: string
  private nextID = 0

  constructor(config: RPCConfig) {
    this.url = config.url
    this.user = config.user
    this.pass = config.password
  }

  /**
   * Invoke a JSON-RPC method on the BSV node.
   * Returns the parsed result.
   */
  async call<T = unknown>(method: string, params: unknown[]): Promise<T> {
    this.nextID++
    const reqBody: RPCRequest = {
      jsonrpc: '1.0',
      id: this.nextID,
      method,
      params,
    }

    let resp: Response
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      }
      if (this.user) {
        headers['Authorization'] =
          'Basic ' + btoa(`${this.user}:${this.pass}`)
      }

      resp = await fetch(this.url, {
        method: 'POST',
        headers,
        body: JSON.stringify(reqBody),
        signal: AbortSignal.timeout(30_000),
      })
    } catch (err) {
      throw new ConnectionFailedError(
        err instanceof Error ? err.message : String(err),
      )
    }

    if (resp.status === 401) {
      throw new AuthFailedError('HTTP 401 unauthorized')
    }

    if (resp.status < 200 || resp.status >= 300) {
      const body = await resp.text().catch(() => '')
      throw new ConnectionFailedError(
        `HTTP ${resp.status}: ${body.slice(0, 1024)}`,
      )
    }

    const rpcResp: RPCResponse = await resp.json()

    if (typeof rpcResp !== 'object' || rpcResp === null) {
      throw new InvalidResponseError('malformed JSON-RPC response')
    }
    if (!('result' in rpcResp) && !('error' in rpcResp)) {
      throw new InvalidResponseError('response missing both result and error fields')
    }

    if (rpcResp.id !== reqBody.id) {
      throw new InvalidResponseError(
        `response ID mismatch: expected ${reqBody.id}, got ${rpcResp.id}`,
      )
    }

    if (rpcResp.error) {
      throw new RPCError(rpcResp.error.code, rpcResp.error.message)
    }

    return rpcResp.result as T
  }

  // -----------------------------------------------------------------------
  // BlockchainService implementation
  // -----------------------------------------------------------------------

  async listUnspent(address: string): Promise<UTXO[]> {
    interface ListUnspentResult {
      txid: string
      vout: number
      amount: number
      scriptPubKey: string
      address: string
      confirmations: number
    }

    const results = await this.call<ListUnspentResult[]>('listunspent', [
      0,
      9999999,
      [address],
    ])

    return results.map((r) => ({
      txid: r.txid,
      vout: r.vout,
      amount: btcToSat(r.amount),
      scriptPubKey: r.scriptPubKey,
      address: r.address,
      confirmations: r.confirmations,
    }))
  }

  async getUTXO(txid: string, vout: number): Promise<UTXO | null> {
    interface GettxoutResult {
      value: number
      confirmations: number
      scriptPubKey: {
        hex: string
        addresses?: string[]
      }
    }

    const result = await this.call<GettxoutResult | null>('gettxout', [
      txid,
      vout,
    ])

    if (result === null) {
      return null
    }

    return {
      txid,
      vout,
      amount: btcToSat(result.value),
      scriptPubKey: result.scriptPubKey.hex,
      address: result.scriptPubKey.addresses?.[0] ?? '',
      confirmations: result.confirmations,
    }
  }

  async broadcastTx(rawTxHex: string): Promise<string> {
    try {
      return await this.call<string>('sendrawtransaction', [rawTxHex])
    } catch (err) {
      if (err instanceof RPCError) {
        throw new BroadcastRejectedError(err.message)
      }
      throw err
    }
  }

  async getRawTx(txid: string): Promise<Uint8Array> {
    const rawHex = await this.call<string>('getrawtransaction', [txid, false])
    return hexToBytes(rawHex)
  }

  async getTxStatus(txid: string): Promise<TxStatus> {
    interface VerboseTxResult {
      confirmations: number
      blockhash?: string
      blockheight?: number
    }

    const result = await this.call<VerboseTxResult>('getrawtransaction', [
      txid,
      true,
    ])

    return {
      confirmed: result.confirmations > 0,
      blockHash: result.blockhash ?? '',
      blockHeight: result.blockheight ?? 0,
      txIndex: 0, // Not available from getrawtransaction verbose
    }
  }

  async getBlockHeader(blockHash: string): Promise<Uint8Array> {
    const headerHex = await this.call<string>('getblockheader', [
      blockHash,
      false,
    ])
    return hexToBytes(headerHex)
  }

  async getMerkleProof(txid: string): Promise<MerkleProofData> {
    const proofHex = await this.call<string>('gettxoutproof', [[txid]])
    const data = hexToBytes(proofHex)

    // Convert display txid (big-endian) to internal byte order.
    const txidBytes = hexToBytes(txid)
    if (txidBytes.length !== 32) {
      throw new InvalidResponseError(
        `txid must be 32 bytes, got ${txidBytes.length}`,
      )
    }
    const targetTxID = reverseBytes(txidBytes)

    const parsed = parseBIP37MerkleBlock(data, targetTxID)

    // Compute block hash in display hex (reversed double-SHA256 of header).
    const blockHash = doubleHash(parsed.header)
    const blockHashHex = bytesToHex(reverseBytes(blockHash))

    return {
      txid,
      blockHash: blockHashHex,
      branches: parsed.branches,
      index: parsed.txIndex,
    }
  }

  async getBestBlockHeight(): Promise<number> {
    return await this.call<number>('getblockcount', [])
  }

  async importAddress(address: string): Promise<void> {
    // params: address, label (empty), rescan (true)
    await this.call<unknown>('importaddress', [address, '', true])
  }

  // -----------------------------------------------------------------------
  // Additional RPC methods (not part of BlockchainService)
  // -----------------------------------------------------------------------

  /** Get block hash by height (used by SPVClient for header sync). */
  async getBlockHash(height: number): Promise<string> {
    return await this.call<string>('getblockhash', [height])
  }
}

// ---------------------------------------------------------------------------
// Utility exports (used by SPVClient and tests)
// ---------------------------------------------------------------------------

export { hexToBytes, reverseBytes, btcToSat, doubleHash }

/** Convert Uint8Array to hex string. */
export function bytesToHex(data: Uint8Array): string {
  let hex = ''
  for (let i = 0; i < data.length; i++) {
    hex += data[i].toString(16).padStart(2, '0')
  }
  return hex
}
