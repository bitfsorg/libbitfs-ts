/** Size of a serialized BSV block header in bytes. */
export const BLOCK_HEADER_SIZE = 80

/** Size of a SHA256 hash in bytes. */
export const HASH_SIZE = 32

/**
 * BlockHeader represents a BSV block header (80 bytes serialized).
 *
 * All numeric fields are stored in little-endian order in the serialized form.
 */
export interface BlockHeader {
  /** Block version (4 bytes, little-endian in wire format). */
  version: number
  /** Hash of the previous block header (32 bytes, internal byte order). */
  prevBlock: Uint8Array
  /** Merkle root of the block's transaction tree (32 bytes, internal byte order). */
  merkleRoot: Uint8Array
  /** Unix timestamp (4 bytes, little-endian in wire format). */
  timestamp: number
  /** Compact target (nBits) (4 bytes, little-endian in wire format). */
  bits: number
  /** Mining nonce (4 bytes, little-endian in wire format). */
  nonce: number
  /** Block height — not in the raw 80-byte header; tracked separately. */
  height: number
  /** Computed double-SHA256 hash of the 80-byte header. */
  hash: Uint8Array
}

/**
 * MerkleProof represents a Merkle inclusion proof for a transaction.
 */
export interface MerkleProof {
  /** Transaction hash (32 bytes). */
  txID: Uint8Array
  /** Position in the block's transaction list. */
  index: number
  /** Merkle branch hashes, bottom-up. */
  nodes: Uint8Array[]
  /** Block header hash this proof is for (32 bytes). */
  blockHash: Uint8Array
}

/**
 * StoredTx represents a transaction stored with its Merkle proof.
 */
export interface StoredTx {
  /** Transaction ID (32 bytes). */
  txID: Uint8Array
  /** Full serialized transaction. */
  rawTx: Uint8Array
  /** Block header hash (32 bytes). */
  blockHash: Uint8Array
  /** Block height (0 = unconfirmed). */
  blockHeight: number
  /** Merkle proof (undefined = unconfirmed). */
  merkleProof?: MerkleProof
}

/**
 * Network identifies the BSV network for difficulty validation.
 */
export enum Network {
  Mainnet = 0,
  Testnet = 1,
  Regtest = 2,
}

/**
 * HeaderStore persists block headers for chain verification.
 */
export interface HeaderStore {
  /** Stores a block header. */
  putHeader(header: BlockHeader): Promise<void>
  /** Retrieves a header by block hash. */
  getHeader(blockHash: Uint8Array): Promise<BlockHeader | null>
  /** Retrieves a header by block height. */
  getHeaderByHeight(height: number): Promise<BlockHeader | null>
  /** Returns the header with the greatest height. */
  getTip(): Promise<BlockHeader | null>
  /** Returns the total number of stored headers. */
  getHeaderCount(): Promise<number>
}

/**
 * TxStore persists transactions with Merkle proofs.
 */
export interface TxStore {
  /** Stores a transaction with optional Merkle proof. */
  putTx(tx: StoredTx): Promise<void>
  /** Retrieves a transaction by TxID. */
  getTx(txID: Uint8Array): Promise<StoredTx | null>
  /** Removes a transaction from the store. */
  deleteTx(txID: Uint8Array): Promise<void>
  /** Returns all stored transactions. */
  listTxs(): Promise<StoredTx[]>
}
