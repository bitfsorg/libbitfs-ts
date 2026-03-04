// metanet/parser — Node <-> TLV payload conversion
//
// SerializePayload encodes a Node's fields into the TLV binary format.
// deserializePayload decodes TLV binary data into a Node.
// ParseNode parses OP_RETURN push data [MetaFlag, P_node, TxID_parent, Payload].

import type { Node } from './types.js'
import { NodeType, AccessLevel, LinkType, createNode, MAX_PAYLOAD_SIZE, COMPRESSED_PUBKEY_LEN, TXID_LEN } from './types.js'
import { MetanetError, ErrInvalidPayload, ErrInvalidOPReturn } from './errors.js'
import { META_FLAG } from '../tx/opreturn.js'
import { timingSafeEqual } from '../util.js'
import type { TxOutput } from '../tx/parse.js'
import { parseTxNodeOps } from '../tx/parse.js'
import {
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
  appendField,
  appendUint32Field,
  appendUint64Field,
  appendStringField,
  readUvarint,
  concat,
  serializeChildEntry,
  deserializeChildEntry,
  serializeMetadata,
  deserializeMetadata,
  serializeISOConfig,
  deserializeISOConfig,
  validateTLVFieldLength,
} from './tlv.js'

const decoder = new TextDecoder()

/**
 * Serializes a Node's fields into the TLV binary payload format.
 * This is the payload portion of the OP_RETURN push data.
 */
export function serializePayload(node: Node): Uint8Array {
  const parts: Uint8Array[] = []

  // Version (always present)
  appendUint32Field(parts, TAG_VERSION, node.version)

  // Type (always present)
  appendUint32Field(parts, TAG_TYPE, node.type)

  // Op (always present)
  appendUint32Field(parts, TAG_OP, node.op)

  // MimeType
  if (node.mimeType !== '') {
    appendStringField(parts, TAG_MIME_TYPE, node.mimeType)
  }

  // FileSize
  if (node.fileSize > 0n) {
    appendUint64Field(parts, TAG_FILE_SIZE, node.fileSize)
  }

  // KeyHash
  if (node.keyHash.length > 0) {
    appendField(parts, TAG_KEY_HASH, node.keyHash)
  }

  // Access (always present)
  appendUint32Field(parts, TAG_ACCESS, node.access)

  // PricePerKB
  if (node.pricePerKB > 0n) {
    appendUint64Field(parts, TAG_PRICE_PER_KB, node.pricePerKB)
  }

  // LinkTarget
  if (node.linkTarget.length > 0) {
    appendField(parts, TAG_LINK_TARGET, node.linkTarget)
  }

  // LinkType (only for link nodes)
  if (node.type === NodeType.Link) {
    appendUint32Field(parts, TAG_LINK_TYPE, node.linkType)
  }

  // Timestamp
  if (node.timestamp > 0n) {
    appendUint64Field(parts, TAG_TIMESTAMP, node.timestamp)
  }

  // Parent P_node
  if (node.parent.length > 0) {
    appendField(parts, TAG_PARENT, node.parent)
  }

  // Index (always present)
  appendUint32Field(parts, TAG_INDEX, node.index)

  // Children
  for (const child of node.children) {
    const childBytes = serializeChildEntry(child)
    appendField(parts, TAG_CHILD_ENTRY, childBytes)
  }

  // NextChildIndex (only for dir nodes)
  if (node.type === NodeType.Dir) {
    appendUint32Field(parts, TAG_NEXT_CHILD_INDEX, node.nextChildIndex)
  }

  // Domain
  if (node.domain !== '') {
    appendStringField(parts, TAG_DOMAIN, node.domain)
  }

  // Keywords
  if (node.keywords !== '') {
    appendStringField(parts, TAG_KEYWORDS, node.keywords)
  }

  // Description
  if (node.description !== '') {
    appendStringField(parts, TAG_DESCRIPTION, node.description)
  }

  // Encrypted
  if (node.encrypted) {
    appendUint32Field(parts, TAG_ENCRYPTED, 1)
  }

  // OnChain
  if (node.onChain) {
    appendUint32Field(parts, TAG_ON_CHAIN, 1)
  }

  // ContentTxIDs
  for (const contentTxID of node.contentTxIDs) {
    appendField(parts, TAG_CONTENT_TXID, contentTxID)
  }

  // Compression
  if (node.compression > 0) {
    appendUint32Field(parts, TAG_COMPRESSION, node.compression)
  }

  // CltvHeight
  if (node.cltvHeight > 0) {
    appendUint32Field(parts, TAG_CLTV_HEIGHT, node.cltvHeight)
  }

  // RevenueShare
  if (node.revenueShare > 0) {
    appendUint32Field(parts, TAG_REVENUE_SHARE, node.revenueShare)
  }

  // NetworkName
  if (node.networkName !== '') {
    appendStringField(parts, TAG_NETWORK_NAME, node.networkName)
  }

  // MerkleRoot
  if (node.merkleRoot !== null && node.merkleRoot.length > 0) {
    appendField(parts, TAG_MERKLE_ROOT, node.merkleRoot)
  }

  // EncPayload
  if (node.encPayload.length > 0) {
    appendField(parts, TAG_ENC_PAYLOAD, node.encPayload)
  }

  // Metadata
  if (node.metadata.size > 0) {
    const metaBytes = serializeMetadata(node.metadata)
    appendField(parts, TAG_METADATA, metaBytes)
  }

  // VersionLog
  if (node.versionLog.length > 0) {
    appendField(parts, TAG_VERSION_LOG, node.versionLog)
  }

  // ShareList
  if (node.shareList.length > 0) {
    appendField(parts, TAG_SHARE_LIST, node.shareList)
  }

  // ChunkIndex
  if (node.chunkIndex > 0) {
    appendUint32Field(parts, TAG_CHUNK_INDEX, node.chunkIndex)
  }

  // TotalChunks
  if (node.totalChunks > 0) {
    appendUint32Field(parts, TAG_TOTAL_CHUNKS, node.totalChunks)
  }

  // RecombinationHash
  if (node.recombinationHash.length > 0) {
    appendField(parts, TAG_RECOMBINATION_HASH, node.recombinationHash)
  }

  // RabinSignature
  if (node.rabinSignature.length > 0) {
    appendField(parts, TAG_RABIN_SIGNATURE, node.rabinSignature)
  }

  // RabinPubKey
  if (node.rabinPubKey.length > 0) {
    appendField(parts, TAG_RABIN_PUB_KEY, node.rabinPubKey)
  }

  // RegistryTxID
  if (node.registryTxID.length > 0) {
    appendField(parts, TAG_REGISTRY_TXID, node.registryTxID)
  }

  // RegistryVout
  if (node.registryVout > 0) {
    appendUint32Field(parts, TAG_REGISTRY_VOUT, node.registryVout)
  }

  // ISOConfig
  if (node.iso !== null) {
    const isoBytes = serializeISOConfig(node.iso)
    appendField(parts, TAG_ISO_CONFIG, isoBytes)
  }

  // ACLRef
  if (node.aclRef.length > 0) {
    appendField(parts, TAG_ACL_REF, node.aclRef)
  }

  // Anchor-specific fields
  if (node.treeRootPNode.length > 0) {
    appendField(parts, TAG_TREE_ROOT_PNODE, node.treeRootPNode)
  }
  if (node.treeRootTxID.length > 0) {
    appendField(parts, TAG_TREE_ROOT_TXID, node.treeRootTxID)
  }
  for (const parentAnchor of node.parentAnchorTxID) {
    appendField(parts, TAG_PARENT_ANCHOR_TXID, parentAnchor)
  }
  if (node.author !== '') {
    appendStringField(parts, TAG_AUTHOR, node.author)
  }
  if (node.commitMessage !== '') {
    appendStringField(parts, TAG_COMMIT_MESSAGE, node.commitMessage)
  }
  if (node.gitCommitSHA.length > 0) {
    appendField(parts, TAG_GIT_COMMIT_SHA, node.gitCommitSHA)
  }
  if (node.fileMode > 0) {
    appendUint32Field(parts, TAG_FILE_MODE, node.fileMode)
  }

  return concat(parts)
}

/**
 * Deserializes a TLV binary payload into the provided Node object.
 * Unknown tags are silently skipped for forward compatibility.
 */
export function deserializePayload(data: Uint8Array, node: Node): void {
  let offset = 0

  while (offset < data.length) {
    const tag = data[offset]
    offset++

    const [length, bytesRead] = readUvarint(data, offset)
    offset += bytesRead

    if (length > MAX_PAYLOAD_SIZE) {
      throw new MetanetError(
        `payload too large: ${length} bytes (max ${MAX_PAYLOAD_SIZE}) for tag 0x${tag.toString(16).padStart(2, '0')}`,
        'ERR_PAYLOAD_TOO_LARGE',
      )
    }

    if (length > data.length - offset) {
      throw new MetanetError(
        `truncated value for tag 0x${tag.toString(16).padStart(2, '0')} at offset ${offset}`,
        'ERR_TRUNCATED_TLV',
      )
    }

    const intLen = length

    // Validate fixed-size fields
    const validationErr = validateTLVFieldLength(tag, intLen)
    if (validationErr !== null) {
      throw new MetanetError(validationErr, 'ERR_INVALID_FIELD_LENGTH')
    }

    const value = data.subarray(offset, offset + intLen)
    offset += intLen

    const dv = new DataView(value.buffer, value.byteOffset, value.byteLength)

    switch (tag) {
      case TAG_VERSION:
        node.version = dv.getUint32(0, true)
        break
      case TAG_TYPE:
        node.type = dv.getUint32(0, true) as NodeType
        break
      case TAG_OP:
        node.op = dv.getUint32(0, true)
        break
      case TAG_MIME_TYPE:
        node.mimeType = decoder.decode(value)
        break
      case TAG_FILE_SIZE: {
        const lo = BigInt(dv.getUint32(0, true))
        const hi = BigInt(dv.getUint32(4, true))
        node.fileSize = (hi << 32n) | lo
        break
      }
      case TAG_KEY_HASH:
        node.keyHash = new Uint8Array(intLen)
        node.keyHash.set(value)
        break
      case TAG_ACCESS:
        node.access = dv.getUint32(0, true) as AccessLevel
        break
      case TAG_PRICE_PER_KB: {
        const lo = BigInt(dv.getUint32(0, true))
        const hi = BigInt(dv.getUint32(4, true))
        node.pricePerKB = (hi << 32n) | lo
        break
      }
      case TAG_LINK_TARGET:
        node.linkTarget = new Uint8Array(intLen)
        node.linkTarget.set(value)
        break
      case TAG_LINK_TYPE:
        node.linkType = dv.getUint32(0, true) as LinkType
        break
      case TAG_TIMESTAMP: {
        const lo = BigInt(dv.getUint32(0, true))
        const hi = BigInt(dv.getUint32(4, true))
        node.timestamp = (hi << 32n) | lo
        break
      }
      case TAG_PARENT:
        node.parent = new Uint8Array(intLen)
        node.parent.set(value)
        break
      case TAG_INDEX:
        node.index = dv.getUint32(0, true)
        break
      case TAG_CHILD_ENTRY: {
        const entry = deserializeChildEntry(new Uint8Array(value))
        node.children.push(entry)
        break
      }
      case TAG_NEXT_CHILD_INDEX:
        node.nextChildIndex = dv.getUint32(0, true)
        break
      case TAG_DOMAIN:
        node.domain = decoder.decode(value)
        break
      case TAG_KEYWORDS:
        node.keywords = decoder.decode(value)
        break
      case TAG_DESCRIPTION:
        node.description = decoder.decode(value)
        break
      case TAG_ENCRYPTED:
        node.encrypted = dv.getUint32(0, true) !== 0
        break
      case TAG_ON_CHAIN:
        node.onChain = dv.getUint32(0, true) !== 0
        break
      case TAG_CONTENT_TXID: {
        const txid = new Uint8Array(intLen)
        txid.set(value)
        node.contentTxIDs.push(txid)
        break
      }
      case TAG_COMPRESSION:
        node.compression = dv.getUint32(0, true)
        break
      case TAG_CLTV_HEIGHT:
        node.cltvHeight = dv.getUint32(0, true)
        break
      case TAG_REVENUE_SHARE:
        node.revenueShare = dv.getUint32(0, true)
        break
      case TAG_NETWORK_NAME:
        node.networkName = decoder.decode(value)
        break
      case TAG_MERKLE_ROOT:
        node.merkleRoot = new Uint8Array(intLen)
        node.merkleRoot.set(value)
        break
      case TAG_ENC_PAYLOAD:
        node.encPayload = new Uint8Array(intLen)
        node.encPayload.set(value)
        break
      case TAG_METADATA: {
        const meta = deserializeMetadata(new Uint8Array(value))
        for (const [k, v] of meta) {
          node.metadata.set(k, v)
        }
        break
      }
      case TAG_VERSION_LOG:
        node.versionLog = new Uint8Array(intLen)
        node.versionLog.set(value)
        break
      case TAG_SHARE_LIST:
        node.shareList = new Uint8Array(intLen)
        node.shareList.set(value)
        break
      case TAG_CHUNK_INDEX:
        node.chunkIndex = dv.getUint32(0, true)
        break
      case TAG_TOTAL_CHUNKS:
        node.totalChunks = dv.getUint32(0, true)
        break
      case TAG_RECOMBINATION_HASH:
        node.recombinationHash = new Uint8Array(intLen)
        node.recombinationHash.set(value)
        break
      case TAG_RABIN_SIGNATURE:
        node.rabinSignature = new Uint8Array(intLen)
        node.rabinSignature.set(value)
        break
      case TAG_RABIN_PUB_KEY:
        node.rabinPubKey = new Uint8Array(intLen)
        node.rabinPubKey.set(value)
        break
      case TAG_REGISTRY_TXID:
        node.registryTxID = new Uint8Array(intLen)
        node.registryTxID.set(value)
        break
      case TAG_REGISTRY_VOUT:
        node.registryVout = dv.getUint32(0, true)
        break
      case TAG_ISO_CONFIG: {
        node.iso = deserializeISOConfig(new Uint8Array(value))
        break
      }
      case TAG_ACL_REF:
        node.aclRef = new Uint8Array(intLen)
        node.aclRef.set(value)
        break

      // Anchor node fields
      case TAG_TREE_ROOT_PNODE:
        node.treeRootPNode = new Uint8Array(intLen)
        node.treeRootPNode.set(value)
        break
      case TAG_TREE_ROOT_TXID:
        node.treeRootTxID = new Uint8Array(intLen)
        node.treeRootTxID.set(value)
        break
      case TAG_PARENT_ANCHOR_TXID: {
        const parentAnchor = new Uint8Array(intLen)
        parentAnchor.set(value)
        node.parentAnchorTxID.push(parentAnchor)
        break
      }
      case TAG_AUTHOR:
        node.author = decoder.decode(value)
        break
      case TAG_COMMIT_MESSAGE:
        node.commitMessage = decoder.decode(value)
        break
      case TAG_GIT_COMMIT_SHA:
        node.gitCommitSHA = new Uint8Array(intLen)
        node.gitCommitSHA.set(value)
        break
      case TAG_FILE_MODE:
        node.fileMode = dv.getUint32(0, true)
        break

      default:
        // Skip unknown tags for forward compatibility
        break
    }
  }
}

/**
 * Parses a TLV binary payload into a new Node.
 * This is a convenience wrapper around createNode() + deserializePayload().
 */
export function parsePayload(data: Uint8Array): Node {
  const node = createNode()
  deserializePayload(data, node)
  return node
}

/**
 * Parses a Metanet node from OP_RETURN push data.
 * Expects pushes: [MetaFlag, P_node, ParentTxID, Payload].
 */
export function parseNodeFromPushes(pushes: Uint8Array[]): Node {
  const invalid = ErrInvalidOPReturn()

  if (pushes.length < 4) {
    throw new MetanetError(
      `${invalid.message}: expected 4 data pushes, got ${pushes.length}`,
      invalid.code,
    )
  }

  if (!timingSafeEqual(pushes[0], META_FLAG)) {
    throw new MetanetError(
      `${invalid.message}: invalid MetaFlag`,
      invalid.code,
    )
  }

  const pNode = pushes[1]
  if (pNode.length !== COMPRESSED_PUBKEY_LEN) {
    throw new MetanetError(
      `${invalid.message}: P_node must be ${COMPRESSED_PUBKEY_LEN} bytes, got ${pNode.length}`,
      invalid.code,
    )
  }

  const parentTxID = pushes[2]
  if (parentTxID.length !== 0 && parentTxID.length !== TXID_LEN) {
    throw new MetanetError(
      `${invalid.message}: parent TxID must be 0 or ${TXID_LEN} bytes, got ${parentTxID.length}`,
      invalid.code,
    )
  }

  const node = parsePayload(pushes[3])
  node.pNode = Uint8Array.from(pNode)
  node.parentTxID = Uint8Array.from(parentTxID)
  return node
}

/**
 * Like parseNodeFromPushes but also sets TxID.
 */
export function parseNodeFromPushesWithTxID(pushes: Uint8Array[], txID: Uint8Array): Node {
  const node = parseNodeFromPushes(pushes)
  if (txID.length === TXID_LEN) {
    node.txID = Uint8Array.from(txID)
  }
  return node
}

/**
 * Like parseNodeFromPushesWithTxID but also sets Vout.
 * Use this when parsing nodes from multi-output batch transactions.
 */
export function parseNodeFromPushesWithOutpoint(
  pushes: Uint8Array[],
  txID: Uint8Array,
  vout: number,
): Node {
  const node = parseNodeFromPushesWithTxID(pushes, txID)
  node.vout = vout
  return node
}

/**
 * Parses all Metanet node operations from transaction outputs and returns
 * populated Node objects with TxID and Vout set.
 *
 * For non-delete ops, Vout is the paired P2PKH node refresh output index.
 * For delete ops, Vout is the OP_RETURN output index.
 */
export function parseTxToNodes(outputs: TxOutput[], txID: Uint8Array): Node[] {
  const ops = parseTxNodeOps(outputs)
  const nodes: Node[] = []

  for (const op of ops) {
    const pushes: Uint8Array[] = [
      META_FLAG,
      op.pNode,
      op.parentTxID,
      op.payload,
    ]

    const vout = op.isDelete ? op.vout : op.nodeVout
    try {
      const node = parseNodeFromPushesWithOutpoint(pushes, txID, vout)
      nodes.push(node)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      throw new MetanetError(`parsing node at vout ${op.vout}: ${msg}`, ErrInvalidPayload().code)
    }
  }

  return nodes
}
