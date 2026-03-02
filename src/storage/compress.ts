import { gzipSync, gunzipSync } from 'node:zlib'
import { ErrUnsupportedCompression, ErrDecompressedTooLarge } from './errors.js'

/** CompressNone indicates no compression. */
export const CompressNone = 0
/** CompressLZW indicates LZW compression (compatible with Go compress/lzw LSB litWidth=8). */
export const CompressLZW = 1
/** CompressGZIP indicates GZIP compression. */
export const CompressGZIP = 2
/** CompressZSTD indicates ZSTD compression (not yet implemented). */
export const CompressZSTD = 3

/** MaxDecompressedSize is the maximum allowed decompressed data size (256 MB). */
export const MAX_DECOMPRESSED_SIZE = 256 * 1024 * 1024

/**
 * Compress compresses data using the specified scheme.
 */
export function compress(data: Uint8Array, scheme: number): Uint8Array {
  switch (scheme) {
    case CompressNone:
      return data
    case CompressLZW:
      return compressLZW(data)
    case CompressGZIP:
      return compressGZIP(data)
    case CompressZSTD:
      throw ErrUnsupportedCompression
    default:
      throw ErrUnsupportedCompression
  }
}

/**
 * Decompress decompresses data using the specified scheme.
 */
export function decompress(data: Uint8Array, scheme: number): Uint8Array {
  switch (scheme) {
    case CompressNone:
      return data
    case CompressLZW:
      return decompressLZW(data)
    case CompressGZIP:
      return decompressGZIP(data)
    case CompressZSTD:
      throw ErrUnsupportedCompression
    default:
      throw ErrUnsupportedCompression
  }
}

// ---------------------------------------------------------------------------
// GZIP
// ---------------------------------------------------------------------------

function compressGZIP(data: Uint8Array): Uint8Array {
  return new Uint8Array(gzipSync(data))
}

function decompressGZIP(data: Uint8Array): Uint8Array {
  const result = new Uint8Array(gunzipSync(data))
  if (result.length > MAX_DECOMPRESSED_SIZE) {
    throw ErrDecompressedTooLarge
  }
  return result
}

// ---------------------------------------------------------------------------
// LZW — Compatible with Go compress/lzw (LSB bit order, litWidth=8)
//
// Go's compress/lzw LSB mode:
// - Literal codes: 0..255 (litWidth=8 → 256 literals)
// - Clear code: 256
// - EOF code: none — stream ends when data runs out
// - Initial code width: litWidth+1 = 9 bits
// - Codes packed LSB first into bytes
// - When next code would exceed current width, width increases by 1
// - Max code width: 12 bits (max code 4095)
// - When table is full (4096 entries), writer emits a clear code and resets
// ---------------------------------------------------------------------------

const LIT_WIDTH = 8
const CLEAR_CODE = 1 << LIT_WIDTH     // 256
const INITIAL_WIDTH = LIT_WIDTH + 1   // 9
const MAX_WIDTH = 12
const MAX_TABLE_SIZE = 1 << MAX_WIDTH // 4096

/**
 * LZW compress compatible with Go compress/lzw LSB litWidth=8.
 *
 * Go's writer:
 * 1. Emits clear code at start
 * 2. Standard LZW with code width starting at 9
 * 3. When table hits max (4096), emits clear code and resets
 * 4. On Close(), emits final string code (and flushes partial byte)
 */
function compressLZW(data: Uint8Array): Uint8Array {
  const writer = new LZWBitWriter()

  // Hi is the code just past the last valid table entry.
  // It starts at CLEAR_CODE + 1 because CLEAR_CODE is the only special code.
  // (Go's LZW has no explicit EOF code; the stream ends when bytes run out.)
  let hi = CLEAR_CODE + 1  // next code to assign = 257
  let width = INITIAL_WIDTH // current bit width = 9

  // The table maps (prefix_code, byte) → new_code.
  // We use a Map<number, number> with a combined key.
  let table = new Map<number, number>()

  // Emit clear code to start.
  writer.writeBits(CLEAR_CODE, width)

  if (data.length === 0) {
    // Nothing to write — just flush.
    writer.flush()
    return writer.toUint8Array()
  }

  // 'code' holds the code for the current match string.
  let code = data[0] // literal code for first byte

  for (let i = 1; i < data.length; i++) {
    const b = data[i]
    const key = (code << 8) | b

    const entry = table.get(key)
    if (entry !== undefined) {
      // Extend the match.
      code = entry
    } else {
      // Emit current match code.
      writer.writeBits(code, width)

      // Add new entry to table.
      if (hi < MAX_TABLE_SIZE) {
        table.set(key, hi)
        hi++
        // Bump width when hi reaches the next power of 2.
        // Go bumps when hi >= 1<<nBits (the next code to assign needs wider codes).
        if (hi >= (1 << width) && width < MAX_WIDTH) {
          width++
        }
      }

      // If the table is full, emit a clear code and reset.
      if (hi >= MAX_TABLE_SIZE) {
        writer.writeBits(CLEAR_CODE, width)
        hi = CLEAR_CODE + 1
        width = INITIAL_WIDTH
        table = new Map()
      }

      // Start new match with current byte.
      code = b
    }
  }

  // Emit the final match code.
  writer.writeBits(code, width)

  writer.flush()
  return writer.toUint8Array()
}

/**
 * LZW decompress compatible with Go compress/lzw LSB litWidth=8.
 */
function decompressLZW(data: Uint8Array): Uint8Array {
  if (data.length === 0) {
    return new Uint8Array(0)
  }

  const reader = new LZWBitReader(data)
  const output: number[] = []

  let width = INITIAL_WIDTH
  let hi = CLEAR_CODE + 1 // next code to assign

  // Table: code → byte sequence.
  // For codes 0..255, the entry is the single byte.
  // We only store entries for codes >= CLEAR_CODE + 1.
  const table: Uint8Array[] = new Array(MAX_TABLE_SIZE)
  for (let i = 0; i < 256; i++) {
    table[i] = new Uint8Array([i])
  }
  // CLEAR_CODE (256) has no string entry.

  // Read the initial clear code.
  const firstCode = reader.readBits(width)
  if (firstCode !== CLEAR_CODE) {
    throw new Error('lzw: missing initial clear code')
  }

  // Read the first actual code after clear.
  let prevCode = reader.readBits(width)
  if (prevCode === -1) {
    // Empty data after clear code.
    return new Uint8Array(0)
  }

  if (prevCode >= 256) {
    throw new Error('lzw: invalid first code after clear')
  }

  // Output the first code's string.
  const firstEntry = table[prevCode]
  for (let j = 0; j < firstEntry.length; j++) {
    output.push(firstEntry[j])
  }

  while (true) {
    if (output.length > MAX_DECOMPRESSED_SIZE) {
      throw ErrDecompressedTooLarge
    }

    const code = reader.readBits(width)
    if (code === -1) {
      // End of data.
      break
    }

    if (code === CLEAR_CODE) {
      // Reset table.
      width = INITIAL_WIDTH
      hi = CLEAR_CODE + 1
      // We keep literal entries 0..255, clear entries above.
      for (let i = CLEAR_CODE + 1; i < MAX_TABLE_SIZE; i++) {
        table[i] = undefined!
      }

      // Read the first code after reset.
      prevCode = reader.readBits(width)
      if (prevCode === -1) {
        break
      }
      if (prevCode >= 256) {
        throw new Error('lzw: invalid code after clear')
      }
      const entry = table[prevCode]
      for (let j = 0; j < entry.length; j++) {
        output.push(entry[j])
      }
      continue
    }

    let entry: Uint8Array
    if (code < hi && table[code] !== undefined) {
      // Code is in the table.
      entry = table[code]
    } else if (code === hi) {
      // Special KwKwK case: code not yet in table.
      const prev = table[prevCode]
      entry = new Uint8Array(prev.length + 1)
      entry.set(prev)
      entry[prev.length] = prev[0]
    } else {
      throw new Error(`lzw: invalid code ${code} (hi=${hi})`)
    }

    // Output the entry.
    for (let j = 0; j < entry.length; j++) {
      output.push(entry[j])
    }

    // Add new table entry: prevCode's string + first char of entry.
    if (hi < MAX_TABLE_SIZE) {
      const prev = table[prevCode]
      const newEntry = new Uint8Array(prev.length + 1)
      newEntry.set(prev)
      newEntry[prev.length] = entry[0]
      table[hi] = newEntry
      hi++

      // The decoder is one table entry behind the encoder (no entry for
      // the first code after clear). To stay in sync with the encoder's
      // width bumps, bump one entry earlier: when hi+1 >= 1<<width.
      if (hi + 1 >= (1 << width) && width < MAX_WIDTH) {
        width++
      }
    }

    prevCode = code
  }

  return new Uint8Array(output)
}

// ---------------------------------------------------------------------------
// Bit-level I/O (LSB first)
// ---------------------------------------------------------------------------

/**
 * Writes variable-width codes packed LSB first into bytes.
 */
class LZWBitWriter {
  private buf: number[] = []
  private bits = 0
  private nBits = 0

  writeBits(code: number, width: number): void {
    this.bits |= code << this.nBits
    this.nBits += width

    while (this.nBits >= 8) {
      this.buf.push(this.bits & 0xff)
      this.bits >>>= 8
      this.nBits -= 8
    }
  }

  flush(): void {
    if (this.nBits > 0) {
      this.buf.push(this.bits & 0xff)
      this.bits = 0
      this.nBits = 0
    }
  }

  toUint8Array(): Uint8Array {
    return new Uint8Array(this.buf)
  }
}

/**
 * Reads variable-width codes packed LSB first from bytes.
 */
class LZWBitReader {
  private data: Uint8Array
  private pos = 0
  private bits = 0
  private nBits = 0

  constructor(data: Uint8Array) {
    this.data = data
  }

  readBits(width: number): number {
    while (this.nBits < width) {
      if (this.pos >= this.data.length) {
        if (this.nBits === 0) {
          return -1 // no more data at all
        }
        // We have partial bits left — return what we have.
        // This handles the final code when the encoder flushed a partial byte.
        // But only if we have enough bits for a valid code.
        if (this.nBits < width) {
          return -1
        }
        break
      }
      this.bits |= this.data[this.pos++] << this.nBits
      this.nBits += 8
    }

    const mask = (1 << width) - 1
    const code = this.bits & mask
    this.bits >>>= width
    this.nBits -= width
    return code
  }
}
