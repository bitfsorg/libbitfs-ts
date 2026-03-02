import { describe, it, expect } from 'vitest'
import {
  compress,
  decompress,
  CompressNone,
  CompressLZW,
  CompressGZIP,
  CompressZSTD,
} from '../compress.js'
import { ErrUnsupportedCompression } from '../errors.js'

function repeat(pattern: Uint8Array, count: number): Uint8Array {
  const result = new Uint8Array(pattern.length * count)
  for (let i = 0; i < count; i++) {
    result.set(pattern, i * pattern.length)
  }
  return result
}

describe('compress/decompress round-trip', () => {
  const data = repeat(
    new TextEncoder().encode('Hello, BitFS! This is test data for compression. '),
    100
  )

  it.each([
    { name: 'none', scheme: CompressNone },
    { name: 'lzw', scheme: CompressLZW },
    { name: 'gzip', scheme: CompressGZIP },
  ])('round-trips with $name', ({ scheme }) => {
    const compressed = compress(data, scheme)
    const decompressed = decompress(compressed, scheme)
    expect(decompressed).toEqual(data)
  })
})

describe('CompressNone identity', () => {
  it('returns the same data unchanged', () => {
    const data = new TextEncoder().encode('unchanged data')
    const compressed = compress(data, CompressNone)
    expect(compressed).toBe(data) // same reference for CompressNone
  })
})

describe('compress empty data', () => {
  it.each([
    { name: 'none', scheme: CompressNone },
    { name: 'lzw', scheme: CompressLZW },
    { name: 'gzip', scheme: CompressGZIP },
  ])('round-trips empty with $name', ({ scheme }) => {
    const compressed = compress(new Uint8Array(0), scheme)
    const decompressed = decompress(compressed, scheme)
    expect(decompressed.length).toBe(0)
  })
})

describe('GZIP produces smaller output', () => {
  it('compresses repetitive data smaller than original', () => {
    const data = repeat(new TextEncoder().encode('AAAA'), 1000)
    const compressed = compress(data, CompressGZIP)
    expect(compressed.length).toBeLessThan(data.length)
  })
})

describe('LZW produces smaller output on repetitive data', () => {
  it('compresses repetitive data', () => {
    const data = repeat(new TextEncoder().encode('ABABAB'), 500)
    const compressed = compress(data, CompressLZW)
    expect(compressed.length).toBeLessThan(data.length)
  })
})

describe('unsupported compression scheme', () => {
  it('throws on compress with ZSTD', () => {
    expect(() => compress(new Uint8Array([1, 2, 3]), CompressZSTD))
      .toThrow(ErrUnsupportedCompression)
  })

  it('throws on decompress with ZSTD', () => {
    expect(() => decompress(new Uint8Array([1, 2, 3]), CompressZSTD))
      .toThrow(ErrUnsupportedCompression)
  })

  it('throws on unknown scheme 99', () => {
    expect(() => compress(new Uint8Array([1, 2, 3]), 99))
      .toThrow(ErrUnsupportedCompression)
  })
})

describe('LZW various data patterns', () => {
  it('handles single byte', () => {
    const data = new Uint8Array([42])
    const compressed = compress(data, CompressLZW)
    const decompressed = decompress(compressed, CompressLZW)
    expect(decompressed).toEqual(data)
  })

  it('handles all byte values 0-255', () => {
    const data = new Uint8Array(256)
    for (let i = 0; i < 256; i++) data[i] = i
    const compressed = compress(data, CompressLZW)
    const decompressed = decompress(compressed, CompressLZW)
    expect(decompressed).toEqual(data)
  })

  it('handles data that triggers table reset (>4KB of diverse patterns)', () => {
    // Large data with enough variety to fill the LZW table and trigger clear codes.
    const data = new Uint8Array(8192)
    for (let i = 0; i < data.length; i++) {
      data[i] = (i * 7 + 13) & 0xff
    }
    const compressed = compress(data, CompressLZW)
    const decompressed = decompress(compressed, CompressLZW)
    expect(decompressed).toEqual(data)
  })

  it('handles highly repetitive data (aaaaaa...)', () => {
    const data = new Uint8Array(10000).fill(0x61)
    const compressed = compress(data, CompressLZW)
    const decompressed = decompress(compressed, CompressLZW)
    expect(decompressed).toEqual(data)
  })

  it('handles two-byte repeating pattern', () => {
    const data = new Uint8Array(5000)
    for (let i = 0; i < data.length; i++) {
      data[i] = i % 2 === 0 ? 0xAA : 0xBB
    }
    const compressed = compress(data, CompressLZW)
    const decompressed = decompress(compressed, CompressLZW)
    expect(decompressed).toEqual(data)
  })

  it('handles random-like data', () => {
    // Pseudo-random data (deterministic for reproducibility).
    const data = new Uint8Array(4096)
    let seed = 12345
    for (let i = 0; i < data.length; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff
      data[i] = seed & 0xff
    }
    const compressed = compress(data, CompressLZW)
    const decompressed = decompress(compressed, CompressLZW)
    expect(decompressed).toEqual(data)
  })
})
