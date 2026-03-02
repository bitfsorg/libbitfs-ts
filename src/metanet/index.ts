// metanet — Metanet protocol types, TLV serialization, directory operations,
// Merkle tree, link/path resolution, and CLTV access control.

// Errors
export {
  MetanetError,
  ErrNotDirectory,
  ErrNotFile,
  ErrNotLink,
  ErrChildNotFound,
  ErrChildExists,
  ErrLinkDepthExceeded,
  ErrRemoteLinkNotSupported,
  ErrInvalidPath,
  ErrNodeNotFound,
  ErrInvalidPayload,
  ErrHardLinkToDirectory,
  ErrNilParam,
  ErrInvalidName,
  ErrAboveRoot,
  ErrInvalidPubKey,
  ErrInvalidOPReturn,
  ErrTotalLinkBudgetExceeded,
} from './errors.js'

// Types, enums, constants
export {
  NodeType,
  OpType,
  LinkType,
  AccessLevel,
  CompressionScheme,
  ISOStatus,
  CLTVResult,
  COMPRESSED_PUBKEY_LEN,
  TXID_LEN,
  MAX_LINK_DEPTH,
  MAX_PATH_COMPONENTS,
  MAX_TOTAL_LINK_FOLLOWS,
  MAX_CHILD_NAME_LEN,
  MAX_PAYLOAD_SIZE,
  createNode,
  isRoot,
  isDir,
  isFile,
  isLink,
  nodeTypeToString,
  opTypeToString,
} from './types.js'
export type { ISOConfig, ChildEntry, Node, ResolveResult, NodeStore } from './types.js'

// TLV encoding/decoding
export {
  // Tag constants
  TAG_VERSION,
  TAG_TYPE,
  TAG_OP,
  TAG_MIME_TYPE,
  TAG_FILE_SIZE,
  TAG_KEY_HASH,
  TAG_ACCESS,
  TAG_PRICE_PER_KB,
  TAG_LINK_TARGET,
  TAG_LINK_TYPE,
  TAG_TIMESTAMP,
  TAG_PARENT,
  TAG_INDEX,
  TAG_CHILD_ENTRY,
  TAG_NEXT_CHILD_INDEX,
  TAG_DOMAIN,
  TAG_KEYWORDS,
  TAG_DESCRIPTION,
  TAG_ENCRYPTED,
  TAG_ON_CHAIN,
  TAG_CONTENT_TXID,
  TAG_COMPRESSION,
  TAG_CLTV_HEIGHT,
  TAG_REVENUE_SHARE,
  TAG_NETWORK_NAME,
  TAG_MERKLE_ROOT,
  TAG_ENC_PAYLOAD,
  TAG_METADATA,
  TAG_VERSION_LOG,
  TAG_SHARE_LIST,
  TAG_CHUNK_INDEX,
  TAG_TOTAL_CHUNKS,
  TAG_RECOMBINATION_HASH,
  TAG_RABIN_SIGNATURE,
  TAG_RABIN_PUB_KEY,
  TAG_REGISTRY_TXID,
  TAG_REGISTRY_VOUT,
  TAG_ISO_CONFIG,
  TAG_ACL_REF,
  TAG_TREE_ROOT_PNODE,
  TAG_TREE_ROOT_TXID,
  TAG_PARENT_ANCHOR_TXID,
  TAG_AUTHOR,
  TAG_COMMIT_MESSAGE,
  TAG_GIT_COMMIT_SHA,
  TAG_FILE_MODE,
  // Varint
  encodeUvarint,
  readUvarint,
  // TLV field builders
  appendField,
  appendUint32Field,
  appendUint64Field,
  appendStringField,
  // Binary format helpers
  serializeChildEntry,
  deserializeChildEntry,
  serializeMetadata,
  deserializeMetadata,
  serializeISOConfig,
  deserializeISOConfig,
  validateTLVFieldLength,
  concat,
} from './tlv.js'

// Parser (Node <-> TLV payload)
export { serializePayload, deserializePayload, parsePayload } from './parser.js'

// Directory operations
export { listDirectory, findChild, addChild, removeChild, renameChild, nextChildIndex } from './directory.js'

// Merkle tree
export {
  doubleHash,
  computeChildLeafHash,
  computeDirectoryMerkleRoot,
  buildDirectoryMerkleProof,
  verifyChildMembership,
} from './merkle.js'

// Link resolution
export { followLink, followLinkCounted, latestVersion, inheritPricePerKB } from './link.js'

// Path resolution
export { splitPath, resolvePath } from './resolve.js'

// CLTV access control
export { checkCLTVAccess } from './cltv.js'
