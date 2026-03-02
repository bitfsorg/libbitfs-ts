import { Hash } from '@bsv/sdk'

/** Rabin key pair: two private primes and the public modulus. */
export interface RabinKeyPair {
  /** Private prime p, where p ≡ 3 (mod 4). */
  p: bigint
  /** Private prime q, where q ≡ 3 (mod 4). */
  q: bigint
  /** Public modulus n = p * q. */
  n: bigint
}

/** Maximum number of padding attempts for quadratic residue search. */
const MAX_RABIN_PADDING_ITERATIONS = 1_000_000

/**
 * Generates a Rabin key pair with primes of bitSize bits each.
 * Both primes p and q satisfy p ≡ 3 (mod 4) (Blum primes).
 */
export async function generateRabinKey(bitSize: number): Promise<RabinKeyPair> {
  const p = await generateBlumPrime(bitSize)
  const q = await generateBlumPrime(bitSize)
  if (p === q) {
    throw new Error('method42: generated identical primes (retry)')
  }
  const n = p * q
  return { p, q, n }
}

/**
 * Signs a message using the Rabin signature scheme.
 * Returns [S, U] where S is the signature (bigint) and U is the 4-byte padding.
 */
export function rabinSign(key: RabinKeyPair, message: Uint8Array): { sig: bigint; pad: Uint8Array } {
  for (let counter = 0; counter < MAX_RABIN_PADDING_ITERATIONS; counter++) {
    const pad = new Uint8Array(4)
    pad[0] = (counter >>> 24) & 0xff
    pad[1] = (counter >>> 16) & 0xff
    pad[2] = (counter >>> 8) & 0xff
    pad[3] = counter & 0xff

    const h = rabinHash(message, pad, key.n)

    // Check if h is a quadratic residue mod p and mod q
    if (!isQuadraticResidue(h, key.p) || !isQuadraticResidue(h, key.q)) {
      continue
    }

    // Compute square root using CRT
    const sp = modSqrtBlum(h, key.p)
    const sq = modSqrtBlum(h, key.q)

    // CRT reconstruction
    const sig = crt(sp, sq, key.p, key.q, key.n)
    return { sig, pad }
  }
  throw new Error(`method42: rabin sign failed after ${MAX_RABIN_PADDING_ITERATIONS} padding iterations`)
}

/**
 * Verifies a Rabin signature using only the public modulus n.
 * Returns true if sig^2 mod n === H(message || pad) mod n.
 */
export function rabinVerify(n: bigint, message: Uint8Array, sig: bigint, pad: Uint8Array): boolean {
  const h = rabinHash(message, pad, n)
  const s2 = mod(sig * sig, n)
  return s2 === h
}

/**
 * Serializes a Rabin signature (sig, pad) for TLV storage.
 * Format: len(S)(4B big-endian) || S bytes || len(U)(4B big-endian) || U bytes
 */
export function serializeRabinSignature(sig: bigint, pad: Uint8Array): Uint8Array {
  const sBytes = bigintToBytes(sig)
  const buf = new Uint8Array(4 + sBytes.length + 4 + pad.length)
  writeUint32BE(buf, 0, sBytes.length)
  buf.set(sBytes, 4)
  const offset = 4 + sBytes.length
  writeUint32BE(buf, offset, pad.length)
  buf.set(pad, offset + 4)
  return buf
}

/**
 * Deserializes a Rabin signature from TLV storage.
 * Returns { sig, pad }.
 */
export function deserializeRabinSignature(data: Uint8Array): { sig: bigint; pad: Uint8Array } {
  if (data.length < 8) {
    throw new Error('rabin signature data too short')
  }
  const sLen = readUint32BE(data, 0)
  if (4 + sLen + 4 > data.length) {
    throw new Error('rabin signature S truncated')
  }
  const sig = bytesToBigint(data.slice(4, 4 + sLen))
  const offset = 4 + sLen
  const uLen = readUint32BE(data, offset)
  if (offset + 4 + uLen > data.length) {
    throw new Error('rabin signature U truncated')
  }
  const pad = new Uint8Array(uLen)
  pad.set(data.slice(offset + 4, offset + 4 + uLen))
  return { sig, pad }
}

/** Serializes a Rabin public key (modulus n) for TLV storage. */
export function serializeRabinPubKey(n: bigint): Uint8Array {
  return bigintToBytes(n)
}

/** Deserializes a Rabin public key from TLV storage. */
export function deserializeRabinPubKey(data: Uint8Array): bigint {
  if (data.length === 0) {
    throw new Error('rabin pubkey data empty')
  }
  return bytesToBigint(data)
}

// --- Internal helpers ---

/** Computes SHA256(message || padding) mod n. */
function rabinHash(message: Uint8Array, padding: Uint8Array, n: bigint): bigint {
  const combined = new Uint8Array(message.length + padding.length)
  combined.set(message)
  combined.set(padding, message.length)
  const hash = Hash.sha256(Array.from(combined))
  const h = bytesToBigint(new Uint8Array(hash))
  return mod(h, n)
}

/** Tests whether a is a quadratic residue mod p using Euler's criterion. */
function isQuadraticResidue(a: bigint, p: bigint): boolean {
  const exp = (p - 1n) >> 1n
  const result = modPow(a, exp, p)
  return result === 1n
}

/** Computes modular square root for Blum primes (p ≡ 3 mod 4): a^((p+1)/4) mod p. */
function modSqrtBlum(a: bigint, p: bigint): bigint {
  const exp = (p + 1n) >> 2n
  return modPow(a, exp, p)
}

/** Chinese Remainder Theorem reconstruction. */
function crt(sp: bigint, sq: bigint, p: bigint, q: bigint, n: bigint): bigint {
  const qInv = modInverse(q, p)
  const pInv = modInverse(p, q)
  const t1 = mod(sp * q % n * qInv, n)
  const t2 = mod(sq * p % n * pInv, n)
  return mod(t1 + t2, n)
}

/** Modular exponentiation: base^exp mod m. Uses square-and-multiply. */
function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  if (m === 1n) return 0n
  let result = 1n
  base = mod(base, m)
  while (exp > 0n) {
    if (exp & 1n) {
      result = mod(result * base, m)
    }
    exp >>= 1n
    base = mod(base * base, m)
  }
  return result
}

/** Modular inverse using extended Euclidean algorithm. */
function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [a, m]
  let [old_s, s] = [1n, 0n]
  while (r !== 0n) {
    const q = old_r / r
    ;[old_r, r] = [r, old_r - q * r]
    ;[old_s, s] = [s, old_s - q * s]
  }
  return mod(old_s, m)
}

/** Non-negative modular reduction. */
function mod(a: bigint, m: bigint): bigint {
  const r = a % m
  return r < 0n ? r + m : r
}

/**
 * Generates a random Blum prime of the given bit size (p ≡ 3 mod 4).
 * Uses Miller-Rabin primality test with high confidence.
 */
async function generateBlumPrime(bitSize: number): Promise<bigint> {
  for (;;) {
    let candidate = randomBigint(bitSize)
    // Set the top bit to ensure it's bitSize bits
    candidate |= (1n << BigInt(bitSize - 1))
    // Set bottom two bits to make it ≡ 3 (mod 4)
    candidate |= 3n

    if (isProbablePrime(candidate, 20)) {
      return candidate
    }
  }
}

/** Generates a random bigint of the given bit size. */
function randomBigint(bitSize: number): bigint {
  const byteSize = Math.ceil(bitSize / 8)
  const bytes = new Uint8Array(byteSize)
  crypto.getRandomValues(bytes)
  // Mask off extra bits in the top byte
  const extraBits = byteSize * 8 - bitSize
  if (extraBits > 0) {
    bytes[0] &= (1 << (8 - extraBits)) - 1
  }
  return bytesToBigint(bytes)
}

/**
 * Miller-Rabin primality test.
 * Returns true if n is probably prime with rounds iterations.
 */
function isProbablePrime(n: bigint, rounds: number): boolean {
  if (n < 2n) return false
  if (n === 2n || n === 3n) return true
  if (n % 2n === 0n) return false

  // Write n-1 as 2^r * d
  let d = n - 1n
  let r = 0
  while (d % 2n === 0n) {
    d >>= 1n
    r++
  }

  // Witness loop
  for (let i = 0; i < rounds; i++) {
    // Pick a random witness in [2, n-2]
    const a = randomInRange(2n, n - 2n)
    let x = modPow(a, d, n)

    if (x === 1n || x === n - 1n) continue

    let found = false
    for (let j = 0; j < r - 1; j++) {
      x = modPow(x, 2n, n)
      if (x === n - 1n) {
        found = true
        break
      }
    }
    if (!found) return false
  }
  return true
}

/** Generates a random bigint in the range [min, max]. */
function randomInRange(min: bigint, max: bigint): bigint {
  const range = max - min + 1n
  const bitLen = range.toString(2).length
  for (;;) {
    const r = randomBigint(bitLen)
    if (r < range) return min + r
  }
}

/** Converts a bigint to a big-endian Uint8Array (no leading zeros unless zero). */
function bigintToBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array([0])
  let hex = n.toString(16)
  if (hex.length % 2 !== 0) hex = '0' + hex
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/** Converts a big-endian Uint8Array to a bigint. */
function bytesToBigint(bytes: Uint8Array): bigint {
  if (bytes.length === 0) return 0n
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return BigInt('0x' + hex)
}

/** Writes a 32-bit unsigned integer in big-endian at the given offset. */
function writeUint32BE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = (value >>> 24) & 0xff
  buf[offset + 1] = (value >>> 16) & 0xff
  buf[offset + 2] = (value >>> 8) & 0xff
  buf[offset + 3] = value & 0xff
}

/** Reads a 32-bit unsigned integer in big-endian from the given offset. */
function readUint32BE(buf: Uint8Array, offset: number): number {
  return (buf[offset] << 24 | buf[offset + 1] << 16 | buf[offset + 2] << 8 | buf[offset + 3]) >>> 0
}
