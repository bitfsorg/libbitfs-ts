// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { sha256 } from '@noble/hashes/sha256'
import { RPCClient, hexToBytes, reverseBytes, btcToSat, bytesToHex } from '../rpc.js'
import {
  ConnectionFailedError,
  AuthFailedError,
  BroadcastRejectedError,
  InvalidResponseError,
  RPCError,
} from '../errors.js'
import {
  NetworkPresets,
  resolveConfig,
} from '../types.js'
import type { RPCConfig, BlockchainService } from '../types.js'
import {
  SPVClient,
  deserializeHeader,
  serializeHeader,
  computeHeaderHash,
  computeMerkleRoot,
} from '../spvclient.js'
import { MockBlockchainService, MemHeaderStore } from '../mock.js'

// ---------------------------------------------------------------------------
// Test helper: create a mock fetch for JSON-RPC responses
// ---------------------------------------------------------------------------

type RPCHandler = (method: string, params: unknown[]) => {
  result?: unknown
  error?: { code: number; message: string } | null
}

function mockFetch(handler: RPCHandler) {
  return vi.fn(async (_url: string, init?: RequestInit) => {
    const body = JSON.parse(init?.body as string)
    const { result, error } = handler(body.method, body.params)

    const resp: Record<string, unknown> = { id: body.id }
    if (error) {
      resp.error = error
    } else {
      resp.result = result
    }

    return {
      status: 200,
      ok: true,
      json: async () => resp,
      text: async () => JSON.stringify(resp),
    } as unknown as Response
  })
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

describe('hexToBytes', () => {
  it('converts valid hex to bytes', () => {
    const bytes = hexToBytes('deadbeef')
    expect(bytes).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  it('handles empty string', () => {
    expect(hexToBytes('')).toEqual(new Uint8Array(0))
  })

  it('throws on odd-length hex', () => {
    expect(() => hexToBytes('abc')).toThrow(InvalidResponseError)
  })

  it('throws on invalid hex characters', () => {
    expect(() => hexToBytes('zzzz')).toThrow(InvalidResponseError)
  })
})

describe('reverseBytes', () => {
  it('reverses bytes', () => {
    const input = new Uint8Array([1, 2, 3, 4])
    const result = reverseBytes(input)
    expect(result).toEqual(new Uint8Array([4, 3, 2, 1]))
  })

  it('returns a new array', () => {
    const input = new Uint8Array([1, 2])
    const result = reverseBytes(input)
    expect(result).not.toBe(input)
  })

  it('handles single byte', () => {
    const result = reverseBytes(new Uint8Array([42]))
    expect(result).toEqual(new Uint8Array([42]))
  })

  it('handles empty array', () => {
    const result = reverseBytes(new Uint8Array(0))
    expect(result).toEqual(new Uint8Array(0))
  })
})

describe('btcToSat', () => {
  it('converts normal values', () => {
    expect(btcToSat(0.001)).toBe(100000n)
    expect(btcToSat(1.0)).toBe(100000000n)
    expect(btcToSat(0.00000001)).toBe(1n)
    expect(btcToSat(1.5)).toBe(150000000n)
  })

  it('returns 0n for zero', () => {
    expect(btcToSat(0)).toBe(0n)
  })

  it('returns 0n for negative values', () => {
    expect(btcToSat(-0.001)).toBe(0n)
    expect(btcToSat(-1.0)).toBe(0n)
  })
})

describe('bytesToHex', () => {
  it('converts bytes to hex string', () => {
    const result = bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
    expect(result).toBe('deadbeef')
  })

  it('pads single-digit bytes with zero', () => {
    const result = bytesToHex(new Uint8Array([0x01, 0x0a]))
    expect(result).toBe('010a')
  })

  it('handles empty array', () => {
    expect(bytesToHex(new Uint8Array(0))).toBe('')
  })
})

// ---------------------------------------------------------------------------
// Network presets
// ---------------------------------------------------------------------------

describe('NetworkPresets', () => {
  it('contains regtest preset', () => {
    expect(NetworkPresets.regtest).toBeDefined()
    expect(NetworkPresets.regtest.url).toBe('http://localhost:18332')
    expect(NetworkPresets.regtest.user).toBe('bitfs')
    expect(NetworkPresets.regtest.password).toBe('bitfs')
    expect(NetworkPresets.regtest.network).toBe('regtest')
  })

  it('contains testnet preset', () => {
    expect(NetworkPresets.testnet).toBeDefined()
    expect(NetworkPresets.testnet.url).toBe('http://localhost:18333')
    expect(NetworkPresets.testnet.network).toBe('testnet')
  })

  it('does not contain mainnet preset', () => {
    expect(NetworkPresets['mainnet']).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// resolveConfig
// ---------------------------------------------------------------------------

describe('resolveConfig', () => {
  it('uses preset for regtest', () => {
    const cfg = resolveConfig(undefined, undefined, 'regtest')
    expect(cfg.url).toBe('http://localhost:18332')
    expect(cfg.user).toBe('bitfs')
    expect(cfg.network).toBe('regtest')
  })

  it('env variables override preset', () => {
    const env = {
      BITFS_RPC_URL: 'http://custom:1234',
      BITFS_RPC_USER: 'myuser',
      BITFS_RPC_PASS: 'mypass',
    }
    const cfg = resolveConfig(undefined, env, 'regtest')
    expect(cfg.url).toBe('http://custom:1234')
    expect(cfg.user).toBe('myuser')
    expect(cfg.password).toBe('mypass')
  })

  it('flags override env and preset', () => {
    const env = { BITFS_RPC_URL: 'http://env:5555' }
    const flags: Partial<RPCConfig> = { url: 'http://flag:6666' }
    const cfg = resolveConfig(flags, env, 'regtest')
    expect(cfg.url).toBe('http://flag:6666')
  })

  it('throws for mainnet without explicit config', () => {
    expect(() => resolveConfig(undefined, undefined, 'mainnet')).toThrow(
      'requires explicit RPC configuration',
    )
  })

  it('mainnet works with explicit config', () => {
    const flags: Partial<RPCConfig> = {
      url: 'http://mainnet:8332',
      user: 'admin',
      password: 'secret',
    }
    const cfg = resolveConfig(flags, undefined, 'mainnet')
    expect(cfg.url).toBe('http://mainnet:8332')
    expect(cfg.network).toBe('mainnet')
  })
})

// ---------------------------------------------------------------------------
// RPCClient — JSON-RPC call structure
// ---------------------------------------------------------------------------

describe('RPCClient', () => {
  let originalFetch: typeof globalThis.fetch

  beforeEach(() => {
    originalFetch = globalThis.fetch
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('sends correct JSON-RPC 1.0 request format', async () => {
    let capturedBody: Record<string, unknown> | null = null
    let capturedHeaders: Record<string, string> = {}

    globalThis.fetch = vi.fn(async (_url: string, init?: RequestInit) => {
      capturedBody = JSON.parse(init?.body as string)
      capturedHeaders = Object.fromEntries(
        Object.entries(init?.headers ?? {}),
      )

      return {
        status: 200,
        ok: true,
        json: async () => ({ id: capturedBody!.id, result: 100 }),
        text: async () => '',
      } as unknown as Response
    })

    const client = new RPCClient({
      url: 'http://localhost:18332',
      user: 'testuser',
      password: 'testpass',
      network: 'regtest',
    })

    await client.call('getblockcount', [])

    // Verify JSON-RPC structure.
    expect(capturedBody).not.toBeNull()
    expect(capturedBody!.jsonrpc).toBe('1.0')
    expect(capturedBody!.method).toBe('getblockcount')
    expect(capturedBody!.params).toEqual([])
    expect(typeof capturedBody!.id).toBe('number')

    // Verify Basic auth.
    expect(capturedHeaders['Content-Type']).toBe('application/json')
    expect(capturedHeaders['Authorization']).toBe(
      'Basic ' + btoa('testuser:testpass'),
    )
  })

  it('sequential calls have incrementing IDs', async () => {
    const ids: number[] = []

    globalThis.fetch = vi.fn(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(init?.body as string)
      ids.push(body.id)
      return {
        status: 200,
        ok: true,
        json: async () => ({ id: body.id, result: 0 }),
        text: async () => '',
      } as unknown as Response
    })

    const client = new RPCClient({
      url: 'http://localhost:18332',
      user: '',
      password: '',
      network: 'regtest',
    })

    await client.call('a', [])
    await client.call('b', [])
    await client.call('c', [])

    expect(ids[0]).toBe(1)
    expect(ids[1]).toBe(2)
    expect(ids[2]).toBe(3)
  })

  it('throws ConnectionFailedError on fetch failure', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error('ECONNREFUSED')
    })

    const client = new RPCClient({
      url: 'http://localhost:1',
      user: '',
      password: '',
      network: 'regtest',
    })

    await expect(client.call('getblockcount', [])).rejects.toThrow(
      ConnectionFailedError,
    )
  })

  it('throws AuthFailedError on 401', async () => {
    globalThis.fetch = vi.fn(async () => ({
      status: 401,
      ok: false,
      text: async () => 'Unauthorized',
    })) as unknown as typeof fetch

    const client = new RPCClient({
      url: 'http://localhost:18332',
      user: 'wrong',
      password: 'creds',
      network: 'regtest',
    })

    await expect(client.call('getblockcount', [])).rejects.toThrow(
      AuthFailedError,
    )
  })

  it('throws ConnectionFailedError on non-2xx status', async () => {
    globalThis.fetch = vi.fn(async () => ({
      status: 500,
      ok: false,
      text: async () => 'Internal Server Error',
    })) as unknown as typeof fetch

    const client = new RPCClient({
      url: 'http://localhost:18332',
      user: '',
      password: '',
      network: 'regtest',
    })

    await expect(client.call('getblockcount', [])).rejects.toThrow(
      ConnectionFailedError,
    )
  })

  it('throws InvalidResponseError on ID mismatch', async () => {
    globalThis.fetch = vi.fn(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(init?.body as string)
      return {
        status: 200,
        ok: true,
        json: async () => ({ id: body.id + 999, result: 42 }),
        text: async () => '',
      } as unknown as Response
    })

    const client = new RPCClient({
      url: 'http://localhost:18332',
      user: '',
      password: '',
      network: 'regtest',
    })

    await expect(client.call('getblockcount', [])).rejects.toThrow(
      InvalidResponseError,
    )
  })

  it('throws RPCError on JSON-RPC error response', async () => {
    globalThis.fetch = vi.fn(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(init?.body as string)
      return {
        status: 200,
        ok: true,
        json: async () => ({
          id: body.id,
          result: null,
          error: { code: -5, message: 'No such mempool transaction' },
        }),
        text: async () => '',
      } as unknown as Response
    })

    const client = new RPCClient({
      url: 'http://localhost:18332',
      user: '',
      password: '',
      network: 'regtest',
    })

    await expect(client.call('getrawtransaction', ['bad'])).rejects.toThrow(
      RPCError,
    )
  })

  it('does not send auth header when user is empty', async () => {
    let capturedHeaders: Record<string, string> = {}

    globalThis.fetch = vi.fn(async (_url: string, init?: RequestInit) => {
      capturedHeaders = Object.fromEntries(
        Object.entries(init?.headers ?? {}),
      )
      const body = JSON.parse(init?.body as string)
      return {
        status: 200,
        ok: true,
        json: async () => ({ id: body.id, result: 0 }),
        text: async () => '',
      } as unknown as Response
    })

    const client = new RPCClient({
      url: 'http://localhost:18332',
      user: '',
      password: '',
      network: 'regtest',
    })

    await client.call('getblockcount', [])
    expect(capturedHeaders['Authorization']).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// RPCClient — BlockchainService methods (via mocked fetch)
// ---------------------------------------------------------------------------

describe('RPCClient BlockchainService methods', () => {
  let originalFetch: typeof globalThis.fetch

  beforeEach(() => {
    originalFetch = globalThis.fetch
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  function makeClient(handler: RPCHandler): RPCClient {
    globalThis.fetch = mockFetch(handler)
    return new RPCClient({
      url: 'http://localhost:18332',
      user: 'bitfs',
      password: 'bitfs',
      network: 'regtest',
    })
  }

  it('listUnspent converts BTC to satoshis', async () => {
    const client = makeClient((method, params) => {
      expect(method).toBe('listunspent')
      expect(params[0]).toBe(0)
      expect(params[1]).toBe(9999999)
      return {
        result: [
          {
            txid: 'abc123',
            vout: 0,
            amount: 0.001,
            scriptPubKey: '76a914dead88ac',
            address: '1Test',
            confirmations: 6,
          },
          {
            txid: 'def456',
            vout: 1,
            amount: 1.5,
            scriptPubKey: '76a914cafe88ac',
            address: '1Test',
            confirmations: 0,
          },
        ],
      }
    })

    const utxos = await client.listUnspent('1Test')
    expect(utxos).toHaveLength(2)
    expect(utxos[0].amount).toBe(100000n) // 0.001 BTC
    expect(utxos[1].amount).toBe(150000000n) // 1.5 BTC
    expect(utxos[0].txid).toBe('abc123')
  })

  it('getUTXO returns UTXO for existing output', async () => {
    const client = makeClient((method, params) => {
      expect(method).toBe('gettxout')
      expect(params[0]).toBe('txid_utxo')
      expect(params[1]).toBe(2)
      return {
        result: {
          value: 0.005,
          confirmations: 3,
          scriptPubKey: {
            hex: '76a914aabb88ac',
            addresses: ['1Addr'],
          },
        },
      }
    })

    const utxo = await client.getUTXO('txid_utxo', 2)
    expect(utxo).not.toBeNull()
    expect(utxo!.amount).toBe(500000n)
    expect(utxo!.address).toBe('1Addr')
  })

  it('getUTXO returns null for spent output', async () => {
    const client = makeClient(() => ({ result: null }))
    const utxo = await client.getUTXO('spent', 0)
    expect(utxo).toBeNull()
  })

  it('broadcastTx sends raw hex and returns txid', async () => {
    const client = makeClient((method, params) => {
      expect(method).toBe('sendrawtransaction')
      expect(params[0]).toBe('0100000001abcdef')
      return { result: 'newtxid123' }
    })

    const txid = await client.broadcastTx('0100000001abcdef')
    expect(txid).toBe('newtxid123')
  })

  it('broadcastTx wraps RPC error as BroadcastRejectedError', async () => {
    const client = makeClient(() => ({
      error: { code: -26, message: 'mandatory-script-verify-flag-failed' },
    }))

    await expect(client.broadcastTx('bad-hex')).rejects.toThrow(
      BroadcastRejectedError,
    )
  })

  it('getRawTx returns decoded bytes', async () => {
    const client = makeClient((method, params) => {
      expect(method).toBe('getrawtransaction')
      expect(params[1]).toBe(false)
      return { result: '0100000001abcdef' }
    })

    const raw = await client.getRawTx('txid123')
    expect(raw).toEqual(hexToBytes('0100000001abcdef'))
  })

  it('getTxStatus returns confirmed status', async () => {
    const client = makeClient((method, params) => {
      expect(method).toBe('getrawtransaction')
      expect(params[1]).toBe(true)
      return {
        result: {
          confirmations: 10,
          blockhash: '000000abc',
          blockheight: 800000,
        },
      }
    })

    const status = await client.getTxStatus('txid456')
    expect(status.confirmed).toBe(true)
    expect(status.blockHash).toBe('000000abc')
    expect(status.blockHeight).toBe(800000)
  })

  it('getTxStatus returns unconfirmed for 0 confirmations', async () => {
    const client = makeClient(() => ({
      result: { confirmations: 0 },
    }))

    const status = await client.getTxStatus('txid789')
    expect(status.confirmed).toBe(false)
  })

  it('getBlockHeader returns 80-byte header', async () => {
    const headerHex =
      '0100000000000000000000000000000000000000000000000000000000000000' +
      '000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa' +
      '4b1e5e4a29ab5f49ffff001d1dac2b7c'

    const client = makeClient((method, params) => {
      expect(method).toBe('getblockheader')
      expect(params[1]).toBe(false)
      return { result: headerHex }
    })

    const header = await client.getBlockHeader('blockhash000')
    expect(header.length).toBe(80)
  })

  it('getBestBlockHeight returns height', async () => {
    const client = makeClient((method) => {
      expect(method).toBe('getblockcount')
      return { result: 850000 }
    })

    const height = await client.getBestBlockHeight()
    expect(height).toBe(850000)
  })

  it('importAddress sends correct params', async () => {
    const client = makeClient((method, params) => {
      expect(method).toBe('importaddress')
      expect(params[0]).toBe('1TestAddr')
      expect(params[1]).toBe('')
      expect(params[2]).toBe(true)
      return { result: null }
    })

    await expect(client.importAddress('1TestAddr')).resolves.toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// SPVClient construction
// ---------------------------------------------------------------------------

describe('SPVClient', () => {
  it('wires up getBlockHash for RPCClient', () => {
    // We can't easily test the actual function without a server,
    // but we can verify it's set.
    const rpc = new RPCClient({
      url: 'http://localhost:18332',
      user: '',
      password: '',
      network: 'regtest',
    })
    const store = new MemHeaderStore()
    const spv = new SPVClient(rpc, store)
    expect(spv.getBlockHash).not.toBeNull()
  })

  it('does not wire getBlockHash for mock', () => {
    const mock = new MockBlockchainService()
    const store = new MemHeaderStore()
    const spv = new SPVClient(mock, store)
    expect(spv.getBlockHash).toBeNull()
  })

  it('verifyTx returns unconfirmed for unconfirmed tx', async () => {
    const mock = new MockBlockchainService()
    mock.setTxStatus('sometxid', {
      confirmed: false,
      blockHash: '',
      blockHeight: 0,
      txIndex: 0,
    })

    const store = new MemHeaderStore()
    const spv = new SPVClient(mock, store)

    const result = await spv.verifyTx('sometxid')
    expect(result.confirmed).toBe(false)
  })

  it('syncHeaders throws when getBlockHash is not configured', async () => {
    const mock = new MockBlockchainService()
    const store = new MemHeaderStore()
    const spv = new SPVClient(mock, store)

    await expect(spv.syncHeaders()).rejects.toThrow(
      'getBlockHash not configured',
    )
  })
})

// ---------------------------------------------------------------------------
// Header serialization
// ---------------------------------------------------------------------------

describe('Header serialization', () => {
  it('deserializeHeader parses 80-byte header', () => {
    const data = new Uint8Array(80)
    const view = new DataView(data.buffer)
    view.setInt32(0, 1, true) // version
    view.setUint32(68, 1700000000, true) // timestamp
    view.setUint32(72, 0x207fffff, true) // bits
    view.setUint32(76, 42, true) // nonce

    const header = deserializeHeader(data)
    expect(header.version).toBe(1)
    expect(header.timestamp).toBe(1700000000)
    expect(header.bits).toBe(0x207fffff)
    expect(header.nonce).toBe(42)
    expect(header.prevBlock.length).toBe(32)
    expect(header.merkleRoot.length).toBe(32)
  })

  it('deserializeHeader throws on wrong size', () => {
    expect(() => deserializeHeader(new Uint8Array(79))).toThrow('expected 80 bytes')
    expect(() => deserializeHeader(new Uint8Array(81))).toThrow('expected 80 bytes')
  })

  it('serializeHeader produces 80 bytes', () => {
    const header = {
      version: 1,
      prevBlock: new Uint8Array(32),
      merkleRoot: new Uint8Array(32),
      timestamp: 1700000000,
      bits: 0x207fffff,
      nonce: 42,
      height: 0,
      hash: new Uint8Array(0),
    }

    const data = serializeHeader(header)
    expect(data.length).toBe(80)

    const view = new DataView(data.buffer)
    expect(view.getInt32(0, true)).toBe(1)
    expect(view.getUint32(68, true)).toBe(1700000000)
    expect(view.getUint32(76, true)).toBe(42)
  })

  it('serialize then deserialize round-trips', () => {
    const original = {
      version: 2,
      prevBlock: new Uint8Array(32).fill(0xab),
      merkleRoot: new Uint8Array(32).fill(0xcd),
      timestamp: 1234567890,
      bits: 0x1d00ffff,
      nonce: 999999,
      height: 100,
      hash: new Uint8Array(0),
    }

    const data = serializeHeader(original)
    const deserialized = deserializeHeader(data)

    expect(deserialized.version).toBe(original.version)
    expect(deserialized.prevBlock).toEqual(original.prevBlock)
    expect(deserialized.merkleRoot).toEqual(original.merkleRoot)
    expect(deserialized.timestamp).toBe(original.timestamp)
    expect(deserialized.bits).toBe(original.bits)
    expect(deserialized.nonce).toBe(original.nonce)
  })

  it('computeHeaderHash produces 32-byte hash', () => {
    const header = {
      version: 1,
      prevBlock: new Uint8Array(32),
      merkleRoot: new Uint8Array(32),
      timestamp: 1700000000,
      bits: 0x207fffff,
      nonce: 0,
      height: 0,
      hash: new Uint8Array(0),
    }

    const hash = computeHeaderHash(header)
    expect(hash.length).toBe(32)

    // Same input should produce same hash.
    const hash2 = computeHeaderHash(header)
    expect(hash).toEqual(hash2)
  })
})

// ---------------------------------------------------------------------------
// Merkle proof computation
// ---------------------------------------------------------------------------

describe('computeMerkleRoot', () => {
  it('returns txHash for empty branches (single-tx block)', () => {
    const txHash = new Uint8Array(32).fill(0x42)
    const root = computeMerkleRoot(txHash, 0, [])
    expect(root).toEqual(txHash)
  })

  it('computes correct root for two-tx block', () => {
    const tx0 = sha256(sha256(new TextEncoder().encode('coinbase')))
    const tx1 = sha256(sha256(new TextEncoder().encode('our-tx')))

    // Compute expected root: H(tx0 || tx1)
    const combined = new Uint8Array(64)
    combined.set(tx0, 0)
    combined.set(tx1, 32)
    const expectedRoot = sha256(sha256(combined))

    // For tx1 at index 1, the branch is [tx0].
    const root = computeMerkleRoot(tx1, 1, [tx0])
    expect(root).toEqual(expectedRoot)

    // For tx0 at index 0, the branch is [tx1].
    const root0 = computeMerkleRoot(tx0, 0, [tx1])
    expect(root0).toEqual(expectedRoot)
  })
})

// ---------------------------------------------------------------------------
// RPCClient as BlockchainService (compile-time check)
// ---------------------------------------------------------------------------

describe('RPCClient implements BlockchainService', () => {
  it('satisfies the BlockchainService interface', () => {
    const client = new RPCClient({
      url: 'http://localhost:18332',
      user: '',
      password: '',
      network: 'regtest',
    })

    // TypeScript compile-time check: RPCClient assignable to BlockchainService.
    const _service: BlockchainService = client
    expect(_service).toBeDefined()
  })
})
