// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/** Unspent transaction output. */
export interface UTXO {
  /** Transaction ID in display hex (big-endian). */
  txid: string
  /** Output index. */
  vout: number
  /** Amount in satoshis. */
  amount: bigint
  /** Locking script in hex. */
  scriptPubKey: string
  /** Address associated with the output. */
  address: string
  /** Number of confirmations (-1 for unconfirmed, 0+ for confirmed). */
  confirmations: number
}

/** Confirmation status of a transaction. */
export interface TxStatus {
  confirmed: boolean
  blockHash: string
  blockHeight: number
  txIndex: number
}

/** Merkle inclusion proof for SPV verification. */
export interface MerkleProofData {
  /** Transaction ID in display hex (big-endian). */
  txid: string
  /** Block hash in display hex (big-endian). */
  blockHash: string
  /** Merkle branch hashes (internal byte order, bottom-up). */
  branches: Uint8Array[]
  /** Position of the target tx in the block. */
  index: number
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Connection parameters for a BSV node's JSON-RPC interface. */
export interface RPCConfig {
  url: string
  user: string
  password: string
  network: string
}

// ---------------------------------------------------------------------------
// BlockchainService — the primary interface for blockchain interaction
// ---------------------------------------------------------------------------

/**
 * BlockchainService is the primary interface for blockchain interaction.
 * Both BitFS and Metanet products import and use this interface.
 */
export interface BlockchainService {
  /** Returns all unspent transaction outputs for the given address. */
  listUnspent(address: string): Promise<UTXO[]>

  /** Returns a specific unspent transaction output by txid and output index. */
  getUTXO(txid: string, vout: number): Promise<UTXO | null>

  /** Submits a raw transaction hex to the network and returns the txid. */
  broadcastTx(rawTxHex: string): Promise<string>

  /** Returns the raw transaction bytes for the given txid. */
  getRawTx(txid: string): Promise<Uint8Array>

  /** Returns the confirmation status of a transaction. */
  getTxStatus(txid: string): Promise<TxStatus>

  /** Returns the raw 80-byte block header for the given block hash. */
  getBlockHeader(blockHash: string): Promise<Uint8Array>

  /** Returns a Merkle inclusion proof for a confirmed transaction. */
  getMerkleProof(txid: string): Promise<MerkleProofData>

  /** Returns the height of the current chain tip. */
  getBestBlockHeight(): Promise<number>

  /**
   * Imports a watch-only address into the node's wallet so that
   * listUnspent can find its UTXOs. Safe to call multiple times.
   */
  importAddress(address: string): Promise<void>
}

// ---------------------------------------------------------------------------
// Network presets
// ---------------------------------------------------------------------------

/**
 * Default RPC configurations for known networks.
 * Mainnet is intentionally omitted to require explicit configuration.
 */
export const NetworkPresets: Record<string, RPCConfig> = {
  regtest: {
    url: 'http://localhost:18332',
    user: 'bitfs',
    password: 'bitfs',
    network: 'regtest',
  },
  testnet: {
    url: 'http://localhost:18333',
    user: 'bitfs',
    password: 'bitfs',
    network: 'testnet',
  },
}

// ---------------------------------------------------------------------------
// Config resolution
// ---------------------------------------------------------------------------

/**
 * Merges RPC configuration from three sources with decreasing priority:
 *  1. CLI flags (highest priority)
 *  2. Environment variables (BITFS_RPC_URL, BITFS_RPC_USER, BITFS_RPC_PASS)
 *  3. Network presets (lowest priority, regtest/testnet only)
 *
 * For mainnet, explicit configuration is required -- there is no preset.
 */
export function resolveConfig(
  flags: Partial<RPCConfig> | undefined,
  env: Record<string, string> | undefined,
  network: string,
): RPCConfig {
  // Layer 1: start with preset defaults if available.
  let result: RPCConfig = NetworkPresets[network]
    ? { ...NetworkPresets[network] }
    : { url: '', user: '', password: '', network }

  result.network = network

  // Layer 2: environment variables override preset defaults.
  if (env) {
    if (env['BITFS_RPC_URL']) result.url = env['BITFS_RPC_URL']
    if (env['BITFS_RPC_USER']) result.user = env['BITFS_RPC_USER']
    if (env['BITFS_RPC_PASS']) result.password = env['BITFS_RPC_PASS']
  }

  // Layer 3: CLI flags have highest priority.
  if (flags) {
    if (flags.url) result.url = flags.url
    if (flags.user) result.user = flags.user
    if (flags.password) result.password = flags.password
  }

  // Validate: URL must be set.
  if (!result.url) {
    throw new Error(
      `network: ${network} requires explicit RPC configuration (set --rpc-url, BITFS_RPC_URL, or config file)`,
    )
  }

  return result
}
