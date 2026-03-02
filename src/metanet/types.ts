// metanet — types and constants for Metanet protocol

// --- Enums ---

/** NodeType represents the Metanet node types. */
export enum NodeType {
  File = 0,
  Dir = 1,
  Link = 2,
  Anchor = 3,
}

/** OpType represents the filesystem operation type. */
export enum OpType {
  Create = 0,
  Update = 1,
  Delete = 2,
}

/** LinkType represents soft link subtypes. */
export enum LinkType {
  /** Points to a P_node within the same vault. */
  Soft = 0,
  /** Points to domain/path across vaults. */
  SoftRemote = 1,
}

/** AccessLevel represents the access control level. */
export enum AccessLevel {
  /** Private: encrypted, owner-only. */
  Private = 0,
  /** Free: publicly readable at no cost. */
  Free = 1,
  /** Paid: requires payment to read. */
  Paid = 2,
}

/** Compression scheme constants. */
export enum CompressionScheme {
  None = 0,
  LZW = 1,
  GZIP = 2,
  ZSTD = 3,
}

/** ISOStatus represents the state of an Initial Share Offering. */
export enum ISOStatus {
  None = 0,
  Open = 1,
  Partial = 2,
  Closed = 3,
}

/** CLTVResult indicates whether content access is allowed based on block height. */
export enum CLTVResult {
  Allowed = 0,
  Denied = 1,
}

// --- Constants ---

/** Length of a compressed public key (33 bytes). */
export const COMPRESSED_PUBKEY_LEN = 33

/** Length of a transaction ID (32 bytes). */
export const TXID_LEN = 32

/** Maximum depth for following a single soft link chain. */
export const MAX_LINK_DEPTH = 10

/** Maximum number of path components in a path resolution. */
export const MAX_PATH_COMPONENTS = 256

/** Global budget for total link follows across an entire ResolvePath call. */
export const MAX_TOTAL_LINK_FOLLOWS = 40

/** Maximum length of a directory entry name in bytes. */
export const MAX_CHILD_NAME_LEN = 255

/** Maximum allowed total payload size for TLV deserialization (64 MB). */
export const MAX_PAYLOAD_SIZE = 64 * 1024 * 1024

// --- Interfaces ---

/** ISOConfig holds ISO (Initial Share Offering) parameters. */
export interface ISOConfig {
  totalShares: bigint
  pricePerShare: bigint
  /** 20 bytes P2PKH hash. */
  creatorAddr: Uint8Array
  status: ISOStatus
}

/** ChildEntry represents a directory entry (Unix dirent). */
export interface ChildEntry {
  /** Child's index within parent directory. */
  index: number
  /** File/directory name (stored only in parent). */
  name: string
  /** FILE / DIR / LINK / ANCHOR. */
  type: NodeType
  /** Child's P_node (33 bytes compressed). */
  pubKey: Uint8Array
  /** True = hardened BIP32 derivation (excluded from dir purchase). */
  hardened: boolean
}

/**
 * Node represents a parsed Metanet node with its payload.
 * All fields match the Go struct for wire compatibility.
 */
export interface Node {
  /** Transaction ID (32 bytes). */
  txID: Uint8Array
  /** P_node compressed public key (33 bytes). */
  pNode: Uint8Array
  /** Parent's TxID (empty for root). */
  parentTxID: Uint8Array
  /** Block height (0 = unconfirmed). */
  blockHeight: number

  // Parsed payload fields
  version: number
  type: NodeType
  op: OpType
  mimeType: string
  fileSize: bigint
  /** SHA256(SHA256(plaintext)). */
  keyHash: Uint8Array
  access: AccessLevel
  pricePerKB: bigint
  /** Target P_node for soft links. */
  linkTarget: Uint8Array
  linkType: LinkType
  timestamp: bigint
  /** Parent P_node. */
  parent: Uint8Array
  /** File index within parent. */
  index: number
  children: ChildEntry[]
  /** Merkle root of Children (32 bytes, null for non-dir or empty dir). */
  merkleRoot: Uint8Array | null
  nextChildIndex: number
  domain: string
  keywords: string
  description: string
  metadata: Map<string, string>
  encrypted: boolean
  /** PRIVATE mode: salt(16B) || nonce(12B) || AES-256-GCM(full TLV) || tag(16B). */
  encPayload: Uint8Array
  onChain: boolean
  contentTxIDs: Uint8Array[]
  compression: number
  cltvHeight: number
  revenueShare: number
  networkName: string

  // Extended fields (Protocol Layer Completion)
  /** P_node pointing to version log node (33 bytes). */
  versionLog: Uint8Array
  /** P_node pointing to share list node (33 bytes). */
  shareList: Uint8Array
  /** Chunk index (0-based) for chunked content. */
  chunkIndex: number
  /** Total number of chunks (0 = not chunked). */
  totalChunks: number
  /** SHA256(chunk0 || chunk1 || ...) (32 bytes). */
  recombinationHash: Uint8Array
  /** Rabin signature (S, U) serialized. */
  rabinSignature: Uint8Array
  /** Rabin public key (modulus n). */
  rabinPubKey: Uint8Array
  /** Registry UTXO TxID (32 bytes). */
  registryTxID: Uint8Array
  /** Registry UTXO output index. */
  registryVout: number
  /** ISO configuration (null = no ISO). */
  iso: ISOConfig | null
  /** ACL reference (group pubkey hash or ACL TxID). */
  aclRef: Uint8Array

  // Anchor-specific fields (NodeTypeAnchor only)
  /** Root directory's P_node (33 bytes). */
  treeRootPNode: Uint8Array
  /** Root directory's latest TxID (32 bytes). */
  treeRootTxID: Uint8Array
  /** Parent anchor TxIDs (merge commits have multiple). */
  parentAnchorTxID: Uint8Array[]
  /** Git commit author. */
  author: string
  /** Git commit message. */
  commitMessage: string
  /** Git commit SHA for cross-reference (20 bytes). */
  gitCommitSHA: Uint8Array
  /** Git file mode (100644, 100755, 120000). */
  fileMode: number
}

/** ResolveResult holds the outcome of a path resolution. */
export interface ResolveResult {
  /** Resolved target node. */
  node: Node
  /** ChildEntry in parent that references this node (null for root). */
  entry: ChildEntry | null
  /** Parent directory node (null for root). */
  parent: Node | null
  /** Fully resolved path components. */
  path: string[]
}

/**
 * NodeStore provides access to Metanet node data.
 * Implementations may read from local txstore or remote daemon.
 */
export interface NodeStore {
  /** Returns the latest version of a node by its P_node. */
  getNodeByPubKey(pNode: Uint8Array): Promise<Node | null>
  /** Returns a specific version of a node by its TxID. */
  getNodeByTxID(txID: Uint8Array): Promise<Node | null>
  /** Returns all versions of a node, ordered by block height desc. */
  getNodeVersions(pNode: Uint8Array): Promise<Node[]>
  /** Returns all child nodes referenced in a directory's ChildEntry list. */
  getChildNodes(dirNode: Node): Promise<Node[]>
}

/** Creates a new empty Node with default values. */
export function createNode(): Node {
  return {
    txID: new Uint8Array(0),
    pNode: new Uint8Array(0),
    parentTxID: new Uint8Array(0),
    blockHeight: 0,
    version: 0,
    type: NodeType.File,
    op: OpType.Create,
    mimeType: '',
    fileSize: 0n,
    keyHash: new Uint8Array(0),
    access: AccessLevel.Private,
    pricePerKB: 0n,
    linkTarget: new Uint8Array(0),
    linkType: LinkType.Soft,
    timestamp: 0n,
    parent: new Uint8Array(0),
    index: 0,
    children: [],
    merkleRoot: null,
    nextChildIndex: 0,
    domain: '',
    keywords: '',
    description: '',
    metadata: new Map(),
    encrypted: false,
    encPayload: new Uint8Array(0),
    onChain: false,
    contentTxIDs: [],
    compression: 0,
    cltvHeight: 0,
    revenueShare: 0,
    networkName: '',
    versionLog: new Uint8Array(0),
    shareList: new Uint8Array(0),
    chunkIndex: 0,
    totalChunks: 0,
    recombinationHash: new Uint8Array(0),
    rabinSignature: new Uint8Array(0),
    rabinPubKey: new Uint8Array(0),
    registryTxID: new Uint8Array(0),
    registryVout: 0,
    iso: null,
    aclRef: new Uint8Array(0),
    treeRootPNode: new Uint8Array(0),
    treeRootTxID: new Uint8Array(0),
    parentAnchorTxID: [],
    author: '',
    commitMessage: '',
    gitCommitSHA: new Uint8Array(0),
    fileMode: 0,
  }
}

/** Returns true if the node has no parent (root of the filesystem). */
export function isRoot(n: Node): boolean {
  return n.parentTxID.length === 0
}

/** Returns true if the node is a directory. */
export function isDir(n: Node): boolean {
  return n.type === NodeType.Dir
}

/** Returns true if the node is a file. */
export function isFile(n: Node): boolean {
  return n.type === NodeType.File
}

/** Returns true if the node is a link. */
export function isLink(n: Node): boolean {
  return n.type === NodeType.Link
}

/** Returns a human-readable string for a NodeType. */
export function nodeTypeToString(nt: NodeType): string {
  switch (nt) {
    case NodeType.File:
      return 'FILE'
    case NodeType.Dir:
      return 'DIR'
    case NodeType.Link:
      return 'LINK'
    case NodeType.Anchor:
      return 'ANCHOR'
    default:
      return 'UNKNOWN'
  }
}

/** Returns a human-readable string for an OpType. */
export function opTypeToString(op: OpType): string {
  switch (op) {
    case OpType.Create:
      return 'CREATE'
    case OpType.Update:
      return 'UPDATE'
    case OpType.Delete:
      return 'DELETE'
    default:
      return 'UNKNOWN'
  }
}
