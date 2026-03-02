import { describe, it, expect } from 'vitest'
import { Hash } from '@bsv/sdk'
import {
  splitIntoChunks,
  recombineChunks,
  computeRecombinationHash,
  DEFAULT_CHUNK_SIZE,
} from '../chunk.js'
import { ErrInvalidChunkSize, ErrRecombinationHashMismatch } from '../errors.js'

function fillBytes(value: number, length: number): Uint8Array {
  return new Uint8Array(length).fill(value)
}

describe('splitIntoChunks', () => {
  it.each([
    { name: 'single chunk', dataSize: 100, chunkSize: 1024, wantChunks: 1 },
    { name: 'exact multiple', dataSize: 3000, chunkSize: 1000, wantChunks: 3 },
    { name: 'non-exact', dataSize: 2500, chunkSize: 1000, wantChunks: 3 },
    { name: 'chunk size 1', dataSize: 5, chunkSize: 1, wantChunks: 5 },
    { name: 'data equals chunk', dataSize: 1000, chunkSize: 1000, wantChunks: 1 },
  ])('$name ($dataSize bytes / $chunkSize chunk)', ({ dataSize, chunkSize, wantChunks }) => {
    const data = fillBytes(0xAB, dataSize)
    const chunks = splitIntoChunks(data, chunkSize)
    expect(chunks).toHaveLength(wantChunks)

    // Recombine and verify.
    const combined = new Uint8Array(dataSize)
    let offset = 0
    for (const chunk of chunks) {
      combined.set(chunk, offset)
      offset += chunk.length
    }
    expect(combined).toEqual(data)
  })

  it('returns empty array for empty data', () => {
    const chunks = splitIntoChunks(new Uint8Array(0))
    expect(chunks).toHaveLength(0)
  })

  it('throws on zero chunk size', () => {
    expect(() => splitIntoChunks(new Uint8Array([1, 2, 3]), 0))
      .toThrow(ErrInvalidChunkSize())
  })

  it('throws on negative chunk size', () => {
    expect(() => splitIntoChunks(new Uint8Array([1, 2, 3]), -1))
      .toThrow(ErrInvalidChunkSize())
  })

  it('uses DEFAULT_CHUNK_SIZE (1MB) when no chunkSize given', () => {
    expect(DEFAULT_CHUNK_SIZE).toBe(1024 * 1024)
    // 3MB data should produce 3 chunks with default 1MB.
    const data = fillBytes(0xCC, 3 * 1024 * 1024)
    const chunks = splitIntoChunks(data)
    expect(chunks).toHaveLength(3)
    expect(chunks[0].length).toBe(1024 * 1024)
    expect(chunks[1].length).toBe(1024 * 1024)
    expect(chunks[2].length).toBe(1024 * 1024)
  })
})

describe('computeRecombinationHash', () => {
  it('computes SHA256 of concatenated chunks', () => {
    const chunks = [
      fillBytes(0x01, 100),
      fillBytes(0x02, 100),
      fillBytes(0x03, 100),
    ]

    const hash = computeRecombinationHash(chunks)
    expect(hash).toHaveLength(32)

    // Verify it matches SHA256 of concatenation.
    const combined = new Uint8Array(300)
    combined.set(chunks[0], 0)
    combined.set(chunks[1], 100)
    combined.set(chunks[2], 200)
    const expected = new Uint8Array(Hash.sha256(combined))
    expect(hash).toEqual(expected)
  })

  it('handles empty chunks array', () => {
    const hash = computeRecombinationHash([])
    expect(hash).toHaveLength(32)
    // SHA256 of empty data.
    const expected = new Uint8Array(Hash.sha256(new Uint8Array(0)))
    expect(hash).toEqual(expected)
  })
})

describe('recombineChunks', () => {
  it('recombines with valid hash', () => {
    const data = fillBytes(0xAA, 2500)
    const chunks = splitIntoChunks(data, 1000)
    const hash = computeRecombinationHash(chunks)

    const result = recombineChunks(chunks, hash)
    expect(result).toEqual(data)
  })

  it('throws on hash mismatch', () => {
    const chunks = [new Uint8Array([0x01]), new Uint8Array([0x02])]
    const badHash = fillBytes(0xFF, 32)

    expect(() => recombineChunks(chunks, badHash))
      .toThrow(ErrRecombinationHashMismatch())
  })

  it('handles empty chunks with correct hash', () => {
    const hash = computeRecombinationHash([])
    const result = recombineChunks([], hash)
    expect(result.length).toBe(0)
  })
})
