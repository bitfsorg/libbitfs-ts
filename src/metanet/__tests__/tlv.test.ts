import { describe, it, expect } from 'vitest'
import {
  encodeUvarint,
  readUvarint,
  appendField,
  appendUint32Field,
  appendUint64Field,
  appendStringField,
  serializeChildEntry,
  deserializeChildEntry,
  serializeMetadata,
  deserializeMetadata,
  serializeISOConfig,
  deserializeISOConfig,
  validateTLVFieldLength,
  concat,
  TAG_VERSION,
  TAG_FILE_SIZE,
  TAG_MERKLE_ROOT,
  TAG_PARENT,
  TAG_GIT_COMMIT_SHA,
  TAG_ISO_CONFIG,
  TAG_MIME_TYPE,
} from '../tlv.js'
import { NodeType, ISOStatus } from '../types.js'
import type { ChildEntry, ISOConfig } from '../types.js'

// --- Varint Tests ---

describe('encodeUvarint / readUvarint', () => {
  it('round-trips value 0', () => {
    const encoded = encodeUvarint(0)
    expect(encoded).toEqual(new Uint8Array([0]))
    const [value, bytesRead] = readUvarint(encoded, 0)
    expect(value).toBe(0)
    expect(bytesRead).toBe(1)
  })

  it('round-trips value 127', () => {
    const encoded = encodeUvarint(127)
    expect(encoded).toEqual(new Uint8Array([127]))
    const [value, bytesRead] = readUvarint(encoded, 0)
    expect(value).toBe(127)
    expect(bytesRead).toBe(1)
  })

  it('round-trips value 128', () => {
    const encoded = encodeUvarint(128)
    expect(encoded).toEqual(new Uint8Array([0x80, 0x01]))
    const [value, bytesRead] = readUvarint(encoded, 0)
    expect(value).toBe(128)
    expect(bytesRead).toBe(2)
  })

  it('round-trips value 16384', () => {
    const encoded = encodeUvarint(16384)
    const [value, bytesRead] = readUvarint(encoded, 0)
    expect(value).toBe(16384)
    expect(bytesRead).toBe(3)
  })

  it('round-trips value 2^32 - 1', () => {
    const val = 0xffffffff
    const encoded = encodeUvarint(val)
    const [value, bytesRead] = readUvarint(encoded, 0)
    expect(value).toBe(val)
    expect(bytesRead).toBe(5)
  })

  it('reads varint at non-zero offset', () => {
    const prefix = new Uint8Array([0xff, 0xff])
    const varint = encodeUvarint(300)
    const combined = concat([prefix, varint])
    const [value, bytesRead] = readUvarint(combined, 2)
    expect(value).toBe(300)
    expect(bytesRead).toBe(2)
  })

  it('throws on truncated varint', () => {
    // 0x80 with no continuation byte
    expect(() => readUvarint(new Uint8Array([0x80]), 0)).toThrow('truncated varint')
  })

  it('rejects negative values', () => {
    expect(() => encodeUvarint(-1)).toThrow()
  })
})

// --- TLV Field Builder Tests ---

describe('TLV field builders', () => {
  it('appendField produces tag + LEB128 length + value', () => {
    const parts: Uint8Array[] = []
    const value = new Uint8Array([0xaa, 0xbb, 0xcc])
    appendField(parts, 0x42, value)
    const result = concat(parts)
    expect(result[0]).toBe(0x42) // tag
    expect(result[1]).toBe(3) // length (fits in 1 byte)
    expect(result.subarray(2)).toEqual(value)
  })

  it('appendUint32Field produces 4-byte LE value', () => {
    const parts: Uint8Array[] = []
    appendUint32Field(parts, TAG_VERSION, 0x01020304)
    const result = concat(parts)
    expect(result[0]).toBe(TAG_VERSION) // tag
    expect(result[1]).toBe(4) // length
    // Little-endian: 04 03 02 01
    expect(result[2]).toBe(0x04)
    expect(result[3]).toBe(0x03)
    expect(result[4]).toBe(0x02)
    expect(result[5]).toBe(0x01)
  })

  it('appendUint64Field produces 8-byte LE value', () => {
    const parts: Uint8Array[] = []
    appendUint64Field(parts, TAG_FILE_SIZE, 0x0102030405060708n)
    const result = concat(parts)
    expect(result[0]).toBe(TAG_FILE_SIZE)
    expect(result[1]).toBe(8)
    // Little-endian: 08 07 06 05 04 03 02 01
    expect(result[2]).toBe(0x08)
    expect(result[3]).toBe(0x07)
    expect(result[4]).toBe(0x06)
    expect(result[5]).toBe(0x05)
    expect(result[6]).toBe(0x04)
    expect(result[7]).toBe(0x03)
    expect(result[8]).toBe(0x02)
    expect(result[9]).toBe(0x01)
  })

  it('appendStringField encodes UTF-8', () => {
    const parts: Uint8Array[] = []
    appendStringField(parts, TAG_MIME_TYPE, 'text/plain')
    const result = concat(parts)
    expect(result[0]).toBe(TAG_MIME_TYPE)
    expect(result[1]).toBe(10) // "text/plain" = 10 bytes
    const decoded = new TextDecoder().decode(result.subarray(2))
    expect(decoded).toBe('text/plain')
  })
})

// --- ChildEntry Tests ---

describe('serializeChildEntry / deserializeChildEntry', () => {
  it('round-trips a basic entry', () => {
    const pubKey = new Uint8Array(33)
    pubKey[0] = 0x02
    for (let i = 1; i < 33; i++) pubKey[i] = i

    const entry: ChildEntry = {
      index: 42,
      name: 'hello.txt',
      type: NodeType.File,
      pubKey,
      hardened: false,
    }

    const serialized = serializeChildEntry(entry)
    const deserialized = deserializeChildEntry(serialized)

    expect(deserialized.index).toBe(42)
    expect(deserialized.name).toBe('hello.txt')
    expect(deserialized.type).toBe(NodeType.File)
    expect(deserialized.pubKey).toEqual(pubKey)
    expect(deserialized.hardened).toBe(false)
  })

  it('round-trips a hardened dir entry', () => {
    const pubKey = new Uint8Array(33)
    pubKey[0] = 0x03
    for (let i = 1; i < 33; i++) pubKey[i] = 0xff - i

    const entry: ChildEntry = {
      index: 0,
      name: 'secrets',
      type: NodeType.Dir,
      pubKey,
      hardened: true,
    }

    const serialized = serializeChildEntry(entry)
    const deserialized = deserializeChildEntry(serialized)

    expect(deserialized.index).toBe(0)
    expect(deserialized.name).toBe('secrets')
    expect(deserialized.type).toBe(NodeType.Dir)
    expect(deserialized.pubKey).toEqual(pubKey)
    expect(deserialized.hardened).toBe(true)
  })

  it('round-trips with unicode name', () => {
    const pubKey = new Uint8Array(33).fill(0xab)
    const entry: ChildEntry = {
      index: 7,
      name: 'cafe\u0301', // "cafe" + combining accent
      type: NodeType.File,
      pubKey,
      hardened: false,
    }

    const serialized = serializeChildEntry(entry)
    const deserialized = deserializeChildEntry(serialized)
    expect(deserialized.name).toBe('cafe\u0301')
  })

  it('throws on truncated data', () => {
    expect(() => deserializeChildEntry(new Uint8Array(3))).toThrow('too short')
  })

  it('throws on truncated name', () => {
    // 4 bytes index + 2 bytes nameLen=100, but no name data
    const buf = new Uint8Array(6)
    const dv = new DataView(buf.buffer)
    dv.setUint32(0, 0, true) // index
    dv.setUint16(4, 100, true) // nameLen = 100
    expect(() => deserializeChildEntry(buf)).toThrow('name truncated')
  })
})

// --- Metadata Tests ---

describe('serializeMetadata / deserializeMetadata', () => {
  it('round-trips empty map', () => {
    const m = new Map<string, string>()
    const serialized = serializeMetadata(m)
    expect(serialized.length).toBe(0)
    const deserialized = deserializeMetadata(serialized)
    expect(deserialized.size).toBe(0)
  })

  it('round-trips single entry', () => {
    const m = new Map([['author', 'satoshi']])
    const serialized = serializeMetadata(m)
    const deserialized = deserializeMetadata(serialized)
    expect(deserialized.size).toBe(1)
    expect(deserialized.get('author')).toBe('satoshi')
  })

  it('round-trips multiple entries', () => {
    const m = new Map([
      ['key1', 'value1'],
      ['key2', 'value2'],
      ['key3', 'value3'],
    ])
    const serialized = serializeMetadata(m)
    const deserialized = deserializeMetadata(serialized)
    expect(deserialized.size).toBe(3)
    expect(deserialized.get('key1')).toBe('value1')
    expect(deserialized.get('key2')).toBe('value2')
    expect(deserialized.get('key3')).toBe('value3')
  })

  it('round-trips unicode keys and values', () => {
    const m = new Map([['emoji_key', 'hello_world']])
    const serialized = serializeMetadata(m)
    const deserialized = deserializeMetadata(serialized)
    expect(deserialized.get('emoji_key')).toBe('hello_world')
  })

  it('throws on truncated key length', () => {
    expect(() => deserializeMetadata(new Uint8Array([0x01]))).toThrow('truncated key length')
  })
})

// --- ISOConfig Tests ---

describe('serializeISOConfig / deserializeISOConfig', () => {
  it('round-trips basic config', () => {
    const addr = new Uint8Array(20)
    for (let i = 0; i < 20; i++) addr[i] = i + 1

    const iso: ISOConfig = {
      totalShares: 1000n,
      pricePerShare: 500n,
      creatorAddr: addr,
      status: ISOStatus.Open,
    }

    const serialized = serializeISOConfig(iso)
    expect(serialized.length).toBe(37)

    const deserialized = deserializeISOConfig(serialized)
    expect(deserialized.totalShares).toBe(1000n)
    expect(deserialized.pricePerShare).toBe(500n)
    expect(deserialized.creatorAddr).toEqual(addr)
    expect(deserialized.status).toBe(ISOStatus.Open)
  })

  it('round-trips large values', () => {
    const iso: ISOConfig = {
      totalShares: 0xfedcba9876543210n,
      pricePerShare: 0x0123456789abcdefn,
      creatorAddr: new Uint8Array(20).fill(0xff),
      status: ISOStatus.Closed,
    }

    const serialized = serializeISOConfig(iso)
    const deserialized = deserializeISOConfig(serialized)
    expect(deserialized.totalShares).toBe(0xfedcba9876543210n)
    expect(deserialized.pricePerShare).toBe(0x0123456789abcdefn)
    expect(deserialized.status).toBe(ISOStatus.Closed)
  })

  it('round-trips zero values', () => {
    const iso: ISOConfig = {
      totalShares: 0n,
      pricePerShare: 0n,
      creatorAddr: new Uint8Array(20),
      status: ISOStatus.None,
    }

    const serialized = serializeISOConfig(iso)
    const deserialized = deserializeISOConfig(serialized)
    expect(deserialized.totalShares).toBe(0n)
    expect(deserialized.pricePerShare).toBe(0n)
    expect(deserialized.status).toBe(ISOStatus.None)
  })

  it('throws on wrong length', () => {
    expect(() => deserializeISOConfig(new Uint8Array(36))).toThrow('37 bytes')
    expect(() => deserializeISOConfig(new Uint8Array(38))).toThrow('37 bytes')
  })
})

// --- TLV Field Length Validation Tests ---

describe('validateTLVFieldLength', () => {
  it('accepts correct uint32 field length', () => {
    expect(validateTLVFieldLength(TAG_VERSION, 4)).toBeNull()
  })

  it('rejects wrong uint32 field length', () => {
    expect(validateTLVFieldLength(TAG_VERSION, 3)).toContain('expected 4 bytes')
  })

  it('accepts correct uint64 field length', () => {
    expect(validateTLVFieldLength(TAG_FILE_SIZE, 8)).toBeNull()
  })

  it('rejects wrong uint64 field length', () => {
    expect(validateTLVFieldLength(TAG_FILE_SIZE, 4)).toContain('expected 8 bytes')
  })

  it('accepts correct 32-byte hash length', () => {
    expect(validateTLVFieldLength(TAG_MERKLE_ROOT, 32)).toBeNull()
  })

  it('rejects wrong hash length', () => {
    expect(validateTLVFieldLength(TAG_MERKLE_ROOT, 16)).toContain('expected 32 bytes')
  })

  it('accepts correct 33-byte pubkey length', () => {
    expect(validateTLVFieldLength(TAG_PARENT, 33)).toBeNull()
  })

  it('rejects wrong pubkey length', () => {
    expect(validateTLVFieldLength(TAG_PARENT, 32)).toContain('expected 33 bytes')
  })

  it('accepts correct git commit SHA length', () => {
    expect(validateTLVFieldLength(TAG_GIT_COMMIT_SHA, 20)).toBeNull()
  })

  it('rejects wrong git commit SHA length', () => {
    expect(validateTLVFieldLength(TAG_GIT_COMMIT_SHA, 32)).toContain('expected 20 bytes')
  })

  it('accepts correct ISO config length', () => {
    expect(validateTLVFieldLength(TAG_ISO_CONFIG, 37)).toBeNull()
  })

  it('returns null for variable-length tags', () => {
    expect(validateTLVFieldLength(TAG_MIME_TYPE, 100)).toBeNull()
  })

  it('returns null for unknown tags', () => {
    expect(validateTLVFieldLength(0xff, 999)).toBeNull()
  })
})

// --- concat ---

describe('concat', () => {
  it('concatenates empty array', () => {
    expect(concat([]).length).toBe(0)
  })

  it('concatenates single array', () => {
    const result = concat([new Uint8Array([1, 2, 3])])
    expect(result).toEqual(new Uint8Array([1, 2, 3]))
  })

  it('concatenates multiple arrays', () => {
    const result = concat([new Uint8Array([1, 2]), new Uint8Array([3, 4, 5]), new Uint8Array([6])])
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]))
  })
})
