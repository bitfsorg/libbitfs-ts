// metanet/tlv — Low-level TLV encoding/decoding
//
// TLV format: tag(1B) + length(unsigned LEB128 varint) + value(length bytes)
// All multi-byte integers are little-endian (matching Go reference implementation).

import type { ChildEntry, ISOConfig } from './types.js'
import { ISOStatus, NodeType } from './types.js'

// --- TLV Tag Constants ---
// Must match Go parser.go exactly for wire compatibility.

export const TAG_VERSION = 0x01
export const TAG_TYPE = 0x02
export const TAG_OP = 0x03
export const TAG_MIME_TYPE = 0x04
export const TAG_FILE_SIZE = 0x05
export const TAG_KEY_HASH = 0x06
export const TAG_ACCESS = 0x07
export const TAG_PRICE_PER_KB = 0x08
export const TAG_LINK_TARGET = 0x09
export const TAG_LINK_TYPE = 0x0a
export const TAG_TIMESTAMP = 0x0b
export const TAG_PARENT = 0x0c
export const TAG_INDEX = 0x0d
export const TAG_CHILD_ENTRY = 0x0e
export const TAG_NEXT_CHILD_INDEX = 0x0f
export const TAG_DOMAIN = 0x10
export const TAG_KEYWORDS = 0x11
export const TAG_DESCRIPTION = 0x12
export const TAG_ENCRYPTED = 0x13
export const TAG_ON_CHAIN = 0x14
export const TAG_CONTENT_TXID = 0x15
export const TAG_COMPRESSION = 0x16
export const TAG_CLTV_HEIGHT = 0x17
export const TAG_REVENUE_SHARE = 0x18
export const TAG_NETWORK_NAME = 0x19
export const TAG_MERKLE_ROOT = 0x1a
export const TAG_ENC_PAYLOAD = 0x1b

// Extended fields
export const TAG_METADATA = 0x1e
export const TAG_VERSION_LOG = 0x1f

// Anchor node tags
export const TAG_TREE_ROOT_PNODE = 0x20
export const TAG_TREE_ROOT_TXID = 0x21
export const TAG_PARENT_ANCHOR_TXID = 0x22
export const TAG_AUTHOR = 0x23
export const TAG_COMMIT_MESSAGE = 0x24
export const TAG_GIT_COMMIT_SHA = 0x25
export const TAG_FILE_MODE = 0x26

// Extended fields (continued, skipping anchor range 0x20-0x26)
export const TAG_SHARE_LIST = 0x27
export const TAG_CHUNK_INDEX = 0x28
export const TAG_TOTAL_CHUNKS = 0x29
export const TAG_RECOMBINATION_HASH = 0x2a
export const TAG_RABIN_SIGNATURE = 0x2b
export const TAG_RABIN_PUB_KEY = 0x2c
export const TAG_REGISTRY_TXID = 0x2d
export const TAG_REGISTRY_VOUT = 0x2e
export const TAG_ISO_CONFIG = 0x2f
export const TAG_ACL_REF = 0x30

// --- Unsigned LEB128 Varint ---

/**
 * Encodes a non-negative integer as unsigned LEB128 varint bytes.
 * Returns a new Uint8Array containing the encoded varint.
 */
export function encodeUvarint(value: number): Uint8Array {
  if (value < 0) throw new RangeError('encodeUvarint: value must be non-negative')
  const bytes: number[] = []
  do {
    let b = value & 0x7f
    value >>>= 7
    if (value !== 0) {
      b |= 0x80
    }
    bytes.push(b)
  } while (value !== 0)
  return new Uint8Array(bytes)
}

/**
 * Decodes an unsigned LEB128 varint from data starting at offset.
 * Returns [value, bytesRead]. Throws on invalid/truncated varint.
 */
export function readUvarint(data: Uint8Array, offset: number): [number, number] {
  let value = 0
  let shift = 0
  let bytesRead = 0
  for (;;) {
    if (offset + bytesRead >= data.length) {
      throw new Error('readUvarint: truncated varint')
    }
    const b = data[offset + bytesRead]
    bytesRead++
    value |= (b & 0x7f) << shift
    if ((b & 0x80) === 0) {
      break
    }
    shift += 7
    if (shift >= 35) {
      throw new Error('readUvarint: varint too long')
    }
  }
  return [value >>> 0, bytesRead] // ensure unsigned
}

// --- TLV Field Builders ---
// These push tag + LEB128 length + value bytes into the output buffer.

const encoder = new TextEncoder()

/** Appends a raw bytes field: tag + LEB128(len) + data. */
export function appendField(parts: Uint8Array[], tag: number, value: Uint8Array): void {
  parts.push(new Uint8Array([tag]))
  parts.push(encodeUvarint(value.length))
  parts.push(value)
}

/** Appends a uint32 field (4 bytes little-endian). */
export function appendUint32Field(parts: Uint8Array[], tag: number, value: number): void {
  const buf = new Uint8Array(4)
  new DataView(buf.buffer).setUint32(0, value, true) // little-endian
  appendField(parts, tag, buf)
}

/** Appends a uint64 field (8 bytes little-endian) from bigint. */
export function appendUint64Field(parts: Uint8Array[], tag: number, value: bigint): void {
  const buf = new Uint8Array(8)
  const dv = new DataView(buf.buffer)
  dv.setUint32(0, Number(value & 0xffffffffn), true)
  dv.setUint32(4, Number((value >> 32n) & 0xffffffffn), true)
  appendField(parts, tag, buf)
}

/** Appends a UTF-8 string field. */
export function appendStringField(parts: Uint8Array[], tag: number, value: string): void {
  appendField(parts, tag, encoder.encode(value))
}

// --- ChildEntry Binary Format ---
// index(4B LE) || nameLen(2B LE) || name(var) || type(4B LE) || pubkeyLen(1B) || pubkey(var) || hardened(1B)

/** Serializes a ChildEntry into its binary format. */
export function serializeChildEntry(entry: ChildEntry): Uint8Array {
  const nameBytes = encoder.encode(entry.name)
  const size = 4 + 2 + nameBytes.length + 4 + 1 + entry.pubKey.length + 1
  const buf = new Uint8Array(size)
  const dv = new DataView(buf.buffer)
  let offset = 0

  // Index (4B LE)
  dv.setUint32(offset, entry.index, true)
  offset += 4

  // Name length (2B LE) + name
  dv.setUint16(offset, nameBytes.length, true)
  offset += 2
  buf.set(nameBytes, offset)
  offset += nameBytes.length

  // Type (4B LE)
  dv.setUint32(offset, entry.type, true)
  offset += 4

  // PubKey length (1B) + pubkey
  buf[offset] = entry.pubKey.length
  offset += 1
  buf.set(entry.pubKey, offset)
  offset += entry.pubKey.length

  // Hardened flag (1B)
  buf[offset] = entry.hardened ? 1 : 0

  return buf
}

/** Deserializes a ChildEntry from its binary format. */
export function deserializeChildEntry(data: Uint8Array): ChildEntry {
  if (data.length < 6) {
    throw new Error('child entry too short')
  }

  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength)
  let offset = 0

  // Index
  const index = dv.getUint32(offset, true)
  offset += 4

  // Name
  const nameLen = dv.getUint16(offset, true)
  offset += 2
  if (offset + nameLen > data.length) {
    throw new Error('child entry name truncated')
  }
  const name = new TextDecoder().decode(data.subarray(offset, offset + nameLen))
  offset += nameLen

  // Type
  if (offset + 4 > data.length) {
    throw new Error('child entry type truncated')
  }
  const type_ = dv.getUint32(offset, true) as NodeType
  offset += 4

  // PubKey
  if (offset + 1 > data.length) {
    throw new Error('child entry pubkey length truncated')
  }
  const pkLen = data[offset]
  offset += 1
  if (offset + pkLen > data.length) {
    throw new Error('child entry pubkey truncated')
  }
  const pubKey = new Uint8Array(pkLen)
  pubKey.set(data.subarray(offset, offset + pkLen))
  offset += pkLen

  // Hardened
  if (offset + 1 > data.length) {
    throw new Error('child entry hardened flag truncated')
  }
  const hardened = data[offset] !== 0

  return { index, name, type: type_, pubKey, hardened }
}

// --- Metadata Binary Format ---
// [keyLen(2B LE) || key(var) || valLen(2B LE) || val(var)]...

/** Serializes a metadata map into its binary format. */
export function serializeMetadata(m: Map<string, string>): Uint8Array {
  const parts: Uint8Array[] = []
  for (const [k, v] of m) {
    const kb = encoder.encode(k)
    const vb = encoder.encode(v)
    const kLen = new Uint8Array(2)
    new DataView(kLen.buffer).setUint16(0, kb.length, true)
    parts.push(kLen)
    parts.push(kb)
    const vLen = new Uint8Array(2)
    new DataView(vLen.buffer).setUint16(0, vb.length, true)
    parts.push(vLen)
    parts.push(vb)
  }
  return concat(parts)
}

/** Deserializes a metadata map from its binary format. */
export function deserializeMetadata(data: Uint8Array): Map<string, string> {
  const m = new Map<string, string>()
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const decoder = new TextDecoder()
  let offset = 0

  while (offset < data.length) {
    if (offset + 2 > data.length) {
      throw new Error(`metadata: truncated key length at offset ${offset}`)
    }
    const kLen = dv.getUint16(offset, true)
    offset += 2
    if (offset + kLen > data.length) {
      throw new Error(`metadata: truncated key at offset ${offset}`)
    }
    const key = decoder.decode(data.subarray(offset, offset + kLen))
    offset += kLen

    if (offset + 2 > data.length) {
      throw new Error(`metadata: truncated value length at offset ${offset}`)
    }
    const vLen = dv.getUint16(offset, true)
    offset += 2
    if (offset + vLen > data.length) {
      throw new Error(`metadata: truncated value at offset ${offset}`)
    }
    const val = decoder.decode(data.subarray(offset, offset + vLen))
    offset += vLen

    m.set(key, val)
  }

  return m
}

// --- ISOConfig Binary Format (37 bytes) ---
// totalShares(8B LE) || pricePerShare(8B LE) || creatorAddr(20B) || status(1B)

/** Serializes an ISOConfig into exactly 37 bytes. */
export function serializeISOConfig(iso: ISOConfig): Uint8Array {
  const buf = new Uint8Array(37)
  const dv = new DataView(buf.buffer)
  // totalShares (8B LE)
  dv.setUint32(0, Number(iso.totalShares & 0xffffffffn), true)
  dv.setUint32(4, Number((iso.totalShares >> 32n) & 0xffffffffn), true)
  // pricePerShare (8B LE)
  dv.setUint32(8, Number(iso.pricePerShare & 0xffffffffn), true)
  dv.setUint32(12, Number((iso.pricePerShare >> 32n) & 0xffffffffn), true)
  // creatorAddr (20B)
  buf.set(iso.creatorAddr.subarray(0, 20), 16)
  // status (1B)
  buf[36] = iso.status
  return buf
}

/** Deserializes an ISOConfig from exactly 37 bytes. */
export function deserializeISOConfig(data: Uint8Array): ISOConfig {
  if (data.length !== 37) {
    throw new Error(`ISO config must be 37 bytes, got ${data.length}`)
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength)

  const totalSharesLo = BigInt(dv.getUint32(0, true))
  const totalSharesHi = BigInt(dv.getUint32(4, true))
  const totalShares = (totalSharesHi << 32n) | totalSharesLo

  const pricePerShareLo = BigInt(dv.getUint32(8, true))
  const pricePerShareHi = BigInt(dv.getUint32(12, true))
  const pricePerShare = (pricePerShareHi << 32n) | pricePerShareLo

  const creatorAddr = new Uint8Array(20)
  creatorAddr.set(data.subarray(16, 36))

  const status = data[36] as ISOStatus

  return { totalShares, pricePerShare, creatorAddr, status }
}

// --- TLV field length validation ---

/** Fixed-size uint32 tags (must be exactly 4 bytes). */
const UINT32_TAGS = new Set([
  TAG_VERSION,
  TAG_TYPE,
  TAG_OP,
  TAG_ACCESS,
  TAG_LINK_TYPE,
  TAG_INDEX,
  TAG_NEXT_CHILD_INDEX,
  TAG_ENCRYPTED,
  TAG_ON_CHAIN,
  TAG_COMPRESSION,
  TAG_CLTV_HEIGHT,
  TAG_REVENUE_SHARE,
  TAG_CHUNK_INDEX,
  TAG_TOTAL_CHUNKS,
  TAG_REGISTRY_VOUT,
  TAG_FILE_MODE,
])

/** Fixed-size uint64 tags (must be exactly 8 bytes). */
const UINT64_TAGS = new Set([TAG_FILE_SIZE, TAG_PRICE_PER_KB, TAG_TIMESTAMP])

/** Fixed-size 32-byte hash/txid tags. */
const HASH32_TAGS = new Set([
  TAG_MERKLE_ROOT,
  TAG_RECOMBINATION_HASH,
  TAG_REGISTRY_TXID,
  TAG_TREE_ROOT_TXID,
  TAG_KEY_HASH,
  TAG_CONTENT_TXID,
  TAG_PARENT_ANCHOR_TXID,
])

/** Fixed-size 33-byte compressed pubkey tags. */
const PUBKEY33_TAGS = new Set([TAG_PARENT, TAG_VERSION_LOG, TAG_SHARE_LIST, TAG_TREE_ROOT_PNODE])

/**
 * Validates that a known fixed-size TLV field has the correct length.
 * Returns null if valid or if the tag is variable-length/unknown.
 * Returns an error message string if the field length is wrong.
 */
export function validateTLVFieldLength(tag: number, length: number): string | null {
  if (UINT32_TAGS.has(tag)) {
    if (length !== 4)
      return `invalid field length for tag 0x${tag.toString(16).padStart(2, '0')}: expected 4 bytes, got ${length}`
  } else if (UINT64_TAGS.has(tag)) {
    if (length !== 8)
      return `invalid field length for tag 0x${tag.toString(16).padStart(2, '0')}: expected 8 bytes, got ${length}`
  } else if (HASH32_TAGS.has(tag)) {
    if (length !== 32)
      return `invalid field length for tag 0x${tag.toString(16).padStart(2, '0')}: expected 32 bytes, got ${length}`
  } else if (PUBKEY33_TAGS.has(tag)) {
    if (length !== 33)
      return `invalid field length for tag 0x${tag.toString(16).padStart(2, '0')}: expected 33 bytes, got ${length}`
  } else if (tag === TAG_GIT_COMMIT_SHA) {
    if (length !== 20)
      return `invalid field length for tag 0x${tag.toString(16).padStart(2, '0')}: expected 20 bytes, got ${length}`
  } else if (tag === TAG_ISO_CONFIG) {
    if (length !== 37)
      return `invalid field length for tag 0x${tag.toString(16).padStart(2, '0')}: expected 37 bytes, got ${length}`
  }
  return null
}

// --- Utility ---

/** Concatenates an array of Uint8Arrays into a single Uint8Array. */
export function concat(parts: Uint8Array[]): Uint8Array {
  let totalLen = 0
  for (const p of parts) totalLen += p.length
  const result = new Uint8Array(totalLen)
  let offset = 0
  for (const p of parts) {
    result.set(p, offset)
    offset += p.length
  }
  return result
}
