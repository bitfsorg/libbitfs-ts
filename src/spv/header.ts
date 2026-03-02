// spv/header — Block header serialization, PoW verification, chain validation

import { BLOCK_HEADER_SIZE, HASH_SIZE, Network } from './types.js'
import type { BlockHeader } from './types.js'
import { SpvError } from './errors.js'
import { doubleHash } from './merkle.js'

// --- Network difficulty constants ---

/** Genesis difficulty for BSV mainnet: 0x1d00ffff. */
export const MAINNET_MIN_BITS = 0x1d00ffff

/** Testnet mirrors mainnet genesis difficulty. */
export const TESTNET_MIN_BITS = 0x1d00ffff

/** Standard regtest minimum: 0x207fffff. */
export const REGTEST_MIN_BITS = 0x207fffff

/**
 * Maximum factor by which nBits can change between two consecutive headers
 * (4x up or down). Simplified bound check for a light client.
 */
const MAX_DIFFICULTY_ADJUSTMENT_FACTOR = 4n

// --- Serialization ---

/**
 * Serializes a BlockHeader to 80 bytes in BSV wire format.
 *
 * Layout: version(4) | prevBlock(32) | merkleRoot(32) | timestamp(4) | bits(4) | nonce(4)
 * All numeric fields are little-endian.
 */
export function serializeHeader(h: BlockHeader): Uint8Array {
  const buf = new Uint8Array(BLOCK_HEADER_SIZE)
  const view = new DataView(buf.buffer)

  view.setInt32(0, h.version, true)  // little-endian
  buf.set(h.prevBlock, 4)
  buf.set(h.merkleRoot, 36)
  view.setUint32(68, h.timestamp, true)
  view.setUint32(72, h.bits, true)
  view.setUint32(76, h.nonce, true)

  return buf
}

/**
 * Deserializes 80 bytes into a BlockHeader.
 * The Hash field is computed from the serialized data.
 */
export function deserializeHeader(data: Uint8Array): BlockHeader {
  if (data.length !== BLOCK_HEADER_SIZE) {
    throw new SpvError(
      `spv: expected ${BLOCK_HEADER_SIZE} bytes, got ${data.length}`,
      'ERR_INVALID_HEADER',
    )
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)

  const prevBlock = new Uint8Array(HASH_SIZE)
  prevBlock.set(data.subarray(4, 36))

  const merkleRoot = new Uint8Array(HASH_SIZE)
  merkleRoot.set(data.subarray(36, 68))

  return {
    version: view.getInt32(0, true),
    prevBlock,
    merkleRoot,
    timestamp: view.getUint32(68, true),
    bits: view.getUint32(72, true),
    nonce: view.getUint32(76, true),
    height: 0,  // Not in raw header; tracked separately
    hash: doubleHash(data),
  }
}

/**
 * Computes and returns the double-SHA256 hash of a block header.
 */
export function computeHeaderHash(h: BlockHeader): Uint8Array {
  const raw = serializeHeader(h)
  return doubleHash(raw)
}

// --- Compact target conversion ---

/**
 * Converts a Bitcoin "compact" (nBits) representation to a 32-byte big-endian
 * target value. Format: 0xEEMMMMMM where EE=exponent, MMMMMM=mantissa.
 */
export function compactToTarget(bits: number): Uint8Array {
  const exponent = bits >>> 24
  let mantissa = bits & 0x007fffff
  // Negative flag (bit 23 of mantissa) -- treat as zero target.
  if ((bits & 0x00800000) !== 0) {
    mantissa = 0
  }

  const target = new Uint8Array(32)
  if (exponent <= 3) {
    mantissa >>>= 8 * (3 - exponent)
    target[31] = mantissa & 0xff
    target[30] = (mantissa >>> 8) & 0xff
    target[29] = (mantissa >>> 16) & 0xff
  } else {
    const pos = 32 - exponent
    if (pos >= 0 && pos < 32) {
      target[pos] = (mantissa >>> 16) & 0xff
    }
    if (pos + 1 >= 0 && pos + 1 < 32) {
      target[pos + 1] = (mantissa >>> 8) & 0xff
    }
    if (pos + 2 >= 0 && pos + 2 < 32) {
      target[pos + 2] = mantissa & 0xff
    }
  }
  return target
}

/**
 * Converts a Bitcoin compact (nBits) representation to a BigInt target value.
 */
export function compactToBigInt(bits: number): bigint {
  const exponent = bits >>> 24
  let mantissa = BigInt(bits & 0x007fffff)
  if ((bits & 0x00800000) !== 0) {
    mantissa = 0n // negative flag
  }

  if (exponent <= 3) {
    return mantissa >> BigInt(8 * (3 - exponent))
  } else {
    return mantissa << BigInt(8 * (exponent - 3))
  }
}

// Precomputed 2^256
const TWO_256 = 1n << 256n

/**
 * Computes the expected number of hashes to find a block at the given compact
 * difficulty: work = 2^256 / (target + 1).
 * Returns 0n for a zero or negative target.
 */
export function workForTarget(bits: number): bigint {
  const target = compactToBigInt(bits)
  if (target <= 0n) return 0n
  return TWO_256 / (target + 1n)
}

/**
 * Computes the total chain work for a sequence of headers.
 */
export function cumulativeWork(headers: BlockHeader[]): bigint {
  let total = 0n
  for (const h of headers) {
    total += workForTarget(h.bits)
  }
  return total
}

// --- PoW verification ---

/**
 * Checks that a block header's hash meets its stated difficulty target.
 * The header hash (interpreted as a big-endian 256-bit integer) must be
 * numerically <= the target derived from bits.
 *
 * Throws SpvError (ERR_INSUFFICIENT_POW) if the hash exceeds the target.
 */
export function verifyPoW(h: BlockHeader): void {
  let hash = h.hash
  if (!hash || hash.length === 0) {
    hash = computeHeaderHash(h)
  }
  const target = compactToTarget(h.bits)

  // Compare hash vs target byte-by-byte in big-endian order (MSB first).
  // SHA256 output is naturally big-endian.
  for (let i = 0; i < 32; i++) {
    if (hash[i] < target[i]) return // hash < target => valid
    if (hash[i] > target[i]) {
      throw new SpvError('spv: hash exceeds target', 'ERR_INSUFFICIENT_POW')
    }
  }
  // hash == target => valid
}

// --- Network difficulty validation ---

/**
 * Returns the minimum nBits (easiest target) for the given network.
 */
export function minBitsForNetwork(net: Network): number {
  switch (net) {
    case Network.Testnet:
      return TESTNET_MIN_BITS
    case Network.Regtest:
      return REGTEST_MIN_BITS
    default:
      return MAINNET_MIN_BITS
  }
}

/**
 * Checks that a header's nBits meets the minimum difficulty for the given
 * network. The minimum difficulty is the easiest target allowed -- a higher
 * nBits target value means less work.
 */
export function validateMinDifficulty(header: BlockHeader, net: Network): void {
  const minBits = minBitsForNetwork(net)
  const minTarget = compactToBigInt(minBits)
  const headerTarget = compactToBigInt(header.bits)

  // A header's target must not exceed the network minimum target.
  // Higher target = easier mining = less security.
  if (headerTarget > minTarget) {
    throw new SpvError(
      `spv: bits 0x${header.bits.toString(16).padStart(8, '0')} exceeds minimum 0x${minBits.toString(16).padStart(8, '0')} for network`,
      'ERR_DIFFICULTY_TOO_LOW',
    )
  }
}

/**
 * Checks that the difficulty change between two consecutive headers does not
 * exceed the allowed bounds (factor of 4).
 */
export function validateDifficultyTransition(prev: BlockHeader, curr: BlockHeader): void {
  const prevTarget = compactToBigInt(prev.bits)
  const currTarget = compactToBigInt(curr.bits)

  // Skip the check if either target is zero (degenerate case).
  if (prevTarget <= 0n || currTarget <= 0n) return

  const maxTarget = prevTarget * MAX_DIFFICULTY_ADJUSTMENT_FACTOR
  if (currTarget > maxTarget) {
    throw new SpvError(
      `spv: target increased by more than ${MAX_DIFFICULTY_ADJUSTMENT_FACTOR}x`,
      'ERR_DIFFICULTY_CHANGE',
    )
  }

  const minTarget = prevTarget / MAX_DIFFICULTY_ADJUSTMENT_FACTOR
  if (currTarget < minTarget) {
    throw new SpvError(
      `spv: target decreased by more than ${MAX_DIFFICULTY_ADJUSTMENT_FACTOR}x`,
      'ERR_DIFFICULTY_CHANGE',
    )
  }
}

// --- Chain verification ---

/**
 * Result of verifying a header chain, including cumulative work.
 */
export interface ChainVerificationResult {
  cumulativeWork: bigint
}

/**
 * Verifies a header chain (PoW + linkage + difficulty) and returns cumulative
 * work. The network parameter controls the minimum difficulty check.
 */
export function verifyHeaderChainWithWork(
  headers: BlockHeader[],
  net: Network,
): ChainVerificationResult {
  if (headers.length === 0) {
    return { cumulativeWork: 0n }
  }

  let totalWork = 0n

  // Validate first header
  verifyPoW(headers[0])
  validateMinDifficulty(headers[0], net)
  totalWork += workForTarget(headers[0].bits)

  for (let i = 1; i < headers.length; i++) {
    const prev = headers[i - 1]
    const curr = headers[i]

    // Compute prev hash if not set
    let prevHash = prev.hash
    if (!prevHash || prevHash.length === 0) {
      prevHash = computeHeaderHash(prev)
    }

    if (curr.prevBlock.length !== HASH_SIZE) {
      throw new SpvError(
        `spv: header at index ${i} has invalid PrevBlock length`,
        'ERR_INVALID_HEADER',
      )
    }

    if (prevHash.length !== HASH_SIZE) {
      throw new SpvError(
        `spv: header at index ${i - 1} has invalid hash`,
        'ERR_INVALID_HEADER',
      )
    }

    // Check linkage
    for (let j = 0; j < HASH_SIZE; j++) {
      if (curr.prevBlock[j] !== prevHash[j]) {
        throw new SpvError(
          `spv: header ${i} PrevBlock does not match header ${i - 1} hash`,
          'ERR_CHAIN_BROKEN',
        )
      }
    }

    // Validate PoW
    verifyPoW(curr)

    // Validate minimum difficulty
    validateMinDifficulty(curr, net)

    // Validate difficulty transition
    validateDifficultyTransition(prev, curr)

    // Accumulate work
    totalWork += workForTarget(curr.bits)
  }

  return { cumulativeWork: totalWork }
}

/**
 * Checks that a sequence of headers forms a valid chain.
 * Each header's PrevBlock must match the previous header's Hash.
 * Headers must be in ascending order (index 0 is earliest).
 *
 * Also verifies PoW for each header.
 */
export function verifyHeaderChain(headers: BlockHeader[]): void {
  if (headers.length === 0) return

  // Validate PoW for first header
  verifyPoW(headers[0])

  for (let i = 1; i < headers.length; i++) {
    const prev = headers[i - 1]
    const curr = headers[i]

    // Compute prev hash if not set
    let prevHash = prev.hash
    if (!prevHash || prevHash.length === 0) {
      prevHash = computeHeaderHash(prev)
    }

    if (curr.prevBlock.length !== HASH_SIZE) {
      throw new SpvError(
        `spv: header at index ${i} has invalid PrevBlock length`,
        'ERR_INVALID_HEADER',
      )
    }

    if (prevHash.length !== HASH_SIZE) {
      throw new SpvError(
        `spv: header at index ${i - 1} has invalid hash`,
        'ERR_INVALID_HEADER',
      )
    }

    for (let j = 0; j < HASH_SIZE; j++) {
      if (curr.prevBlock[j] !== prevHash[j]) {
        throw new SpvError(
          `spv: header ${i} PrevBlock does not match header ${i - 1} hash`,
          'ERR_CHAIN_BROKEN',
        )
      }
    }

    // Validate PoW for each subsequent header
    verifyPoW(curr)
  }
}
