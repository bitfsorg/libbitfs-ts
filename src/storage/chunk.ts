import { Hash } from '@bsv/sdk'
import { ErrInvalidChunkSize, ErrRecombinationHashMismatch } from './errors.js'

/** DefaultChunkSize is the default chunk size for content splitting (1MB). */
export const DEFAULT_CHUNK_SIZE = 1024 * 1024

/**
 * SplitIntoChunks splits data into fixed-size chunks.
 * The last chunk may be smaller than chunkSize.
 */
export function splitIntoChunks(data: Uint8Array, chunkSize: number = DEFAULT_CHUNK_SIZE): Uint8Array[] {
  if (chunkSize <= 0) {
    throw ErrInvalidChunkSize
  }
  if (data.length === 0) {
    return []
  }

  const chunks: Uint8Array[] = []
  for (let i = 0; i < data.length; i += chunkSize) {
    const end = Math.min(i + chunkSize, data.length)
    chunks.push(data.slice(i, end))
  }
  return chunks
}

/**
 * ComputeRecombinationHash computes SHA256(chunk0 || chunk1 || ...).
 */
export function computeRecombinationHash(chunks: Uint8Array[]): Uint8Array {
  // Concatenate all chunks and SHA256 them.
  let totalLen = 0
  for (const chunk of chunks) {
    totalLen += chunk.length
  }
  const combined = new Uint8Array(totalLen)
  let offset = 0
  for (const chunk of chunks) {
    combined.set(chunk, offset)
    offset += chunk.length
  }
  return new Uint8Array(Hash.sha256(combined))
}

/**
 * RecombineChunks concatenates chunks and verifies the recombination hash.
 */
export function recombineChunks(chunks: Uint8Array[], expectedHash: Uint8Array): Uint8Array {
  let totalLen = 0
  for (const chunk of chunks) {
    totalLen += chunk.length
  }
  const combined = new Uint8Array(totalLen)
  let offset = 0
  for (const chunk of chunks) {
    combined.set(chunk, offset)
    offset += chunk.length
  }

  const actualHash = new Uint8Array(Hash.sha256(combined))
  if (actualHash.length !== expectedHash.length) {
    throw ErrRecombinationHashMismatch
  }
  for (let i = 0; i < actualHash.length; i++) {
    if (actualHash[i] !== expectedHash[i]) {
      throw ErrRecombinationHashMismatch
    }
  }
  return combined
}
