import type { PrivateKey, PublicKey } from '@bsv/sdk'

/**
 * UTXO represents an unspent transaction output tracked by the wallet.
 */
export interface UTXO {
  /** Transaction ID (32 bytes, internal byte order). */
  txID: Uint8Array
  /** Output index. */
  vout: number
  /** Amount in satoshis. */
  amount: bigint
  /** Locking script bytes. */
  scriptPubKey: Uint8Array
  /** Signing key (not serialized). */
  privateKey?: PrivateKey
}

/**
 * BatchOpType identifies the kind of operation in a batch.
 */
export enum BatchOpType {
  /** Create a new child node (OP_RETURN + P2PKH refresh). */
  Create = 0,
  /** Update existing node (OP_RETURN + P2PKH refresh). */
  Update = 1,
  /** Delete node (OP_RETURN only, no P2PKH -- UTXO dies). */
  Delete = 2,
  /** Create root node (no input UTXO, OP_RETURN + P2PKH refresh). */
  CreateRoot = 3,
}

/**
 * BatchNodeOp represents one node operation within a MutationBatch.
 */
export interface BatchNodeOp {
  /** Operation type. */
  type: BatchOpType
  /** Node's public key. */
  pubKey: PublicKey
  /** Parent's TxID (for OP_RETURN field 2). Empty/undefined for root. */
  parentTxID: Uint8Array
  /** Serialized TLV payload. */
  payload: Uint8Array
  /** UTXO to spend (undefined for new creates -- no existing UTXO). */
  inputUTXO?: UTXO
  /** Signing key for this node's input. */
  privateKey?: PrivateKey
}

/**
 * BatchResult holds the built transaction and per-op output mapping.
 */
export interface BatchResult {
  /** Serialized unsigned TX. */
  rawTx: Uint8Array
  /** TX hash (computed after signing). */
  txID: Uint8Array
  /** One per op, in order. */
  nodeOps: BatchNodeResult[]
  /** Change output (undefined if dust). */
  changeUTXO?: UTXO
}

/**
 * BatchNodeResult tracks the outputs for one operation.
 */
export interface BatchNodeResult {
  /** Output index of the OP_RETURN. */
  opReturnVout: number
  /** Output index of the P2PKH dust output. */
  nodeVout: number
  /** The produced P_node UTXO. */
  nodeUTXO?: UTXO
}
