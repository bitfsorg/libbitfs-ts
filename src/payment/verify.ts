import { Transaction, Script, OP, Hash } from '@bsv/sdk'
import type { PaymentProof, Invoice } from './types.js'
import {
  ErrInvalidParams,
  ErrInvoiceExpired,
  ErrInvalidTx,
  ErrInsufficientPayment,
  ErrNoMatchingOutput,
  ErrInvalidPreimage,
} from './errors.js'
import { computeCapsuleHash } from '../method42/capsule.js'
import { timingSafeEqual } from '../util.js'

// ---------------------------------------------------------------------------
// Payment verification
// ---------------------------------------------------------------------------

/**
 * Checks that a submitted transaction contains an output paying the
 * required invoice amount to the invoice address.
 *
 * WARNING: This function does NOT verify input signatures. Callers MUST
 * independently confirm the transaction is accepted by the network
 * (mempool or confirmed) before delivering content.
 *
 * WARNING: This function does NOT bind the payment to a specific InvoiceID.
 * Callers MUST track used TxIDs to prevent cross-invoice payment reuse.
 *
 * @returns Transaction ID (hex string) on success for caller tracking.
 */
export function verifyPayment(proof: PaymentProof, invoice: Invoice): string {
  if (proof == null) {
    throw new Error(`${ErrInvalidParams().message}: nil payment proof`)
  }
  if (invoice == null) {
    throw new Error(`${ErrInvalidParams().message}: nil invoice`)
  }

  // Check invoice expiry.
  const now = Math.floor(Date.now() / 1000)
  if (now > invoice.expiry) {
    throw ErrInvoiceExpired()
  }

  // Deserialize the transaction.
  if (proof.rawTx.length === 0) {
    throw new Error(`${ErrInvalidTx().message}: empty raw transaction`)
  }

  let tx: Transaction
  try {
    tx = Transaction.fromBinary(Array.from(proof.rawTx))
  } catch (err) {
    throw new Error(`${ErrInvalidTx().message}: ${err}`)
  }

  // Decode the expected payment address to get the expected PKH.
  // BSV P2PKH address is base58check-encoded: [version(1) || pubKeyHash(20) || checksum(4)]
  const expectedPKH = addressToPKH(invoice.paymentAddr)
  if (expectedPKH == null) {
    throw new Error(`${ErrInvalidParams().message}: invalid invoice address: ${invoice.paymentAddr}`)
  }

  // Search for a matching output.
  for (const output of tx.outputs) {
    if (output.lockingScript == null) {
      continue
    }

    // Check if the output is a P2PKH.
    if (!isP2PKH(output.lockingScript.toBinary())) {
      continue
    }

    // Extract the PKH from the P2PKH script.
    const outputPKH = extractPKH(output.lockingScript.toBinary())
    if (outputPKH == null) {
      continue
    }

    if (!timingSafeEqual(outputPKH, expectedPKH)) {
      continue
    }

    // Check amount.
    const satoshis = BigInt(output.satoshis ?? 0)
    if (satoshis < invoice.price) {
      throw new Error(
        `${ErrInsufficientPayment().message}: output has ${satoshis} satoshis, need ${invoice.price}`,
      )
    }

    // Found a matching output.
    return tx.id('hex') as string
  }

  throw ErrNoMatchingOutput()
}

// ---------------------------------------------------------------------------
// HTLC preimage extraction
// ---------------------------------------------------------------------------

/**
 * Extracts the capsule (preimage) from a spent HTLC input.
 * The spending transaction's unlocking script for the seller claim path is:
 *
 *   <sig> <seller_pubkey> <capsule> OP_TRUE
 *
 * Where OP_TRUE selects the IF branch.
 *
 * If expectedCapsuleHash is non-null, verifies SHA256(fileTxID || preimage)
 * matches before returning.
 *
 * @param spendingTx Serialized spending transaction.
 * @param expectedCapsuleHash Expected hash (32 bytes), or null to skip verification.
 * @param fileTxID Optional 32-byte file transaction ID for hash binding.
 * @returns The extracted preimage (capsule).
 */
export function parseHTLCPreimage(
  spendingTx: Uint8Array,
  expectedCapsuleHash: Uint8Array | null,
  fileTxID?: Uint8Array,
): Uint8Array {
  if (spendingTx == null || spendingTx.length === 0) {
    throw new Error(`${ErrInvalidPreimage().message}: empty spending transaction`)
  }

  if (expectedCapsuleHash && !fileTxID) {
    throw new Error(`${ErrInvalidParams().message}: fileTxID required when expectedCapsuleHash is provided`)
  }

  let tx: Transaction
  try {
    tx = Transaction.fromBinary(Array.from(spendingTx))
  } catch (err) {
    throw new Error(`${ErrInvalidTx().message}: ${err}`)
  }

  // Look through all inputs for an HTLC spend.
  for (const input of tx.inputs) {
    if (input.unlockingScript == null) {
      continue
    }

    const chunks = input.unlockingScript.chunks
    if (chunks == null) {
      continue
    }

    // Seller claim unlocking script: <sig> <pubkey> <preimage> OP_TRUE
    // We expect at least 4 chunks.
    if (chunks.length < 4) {
      continue
    }

    // The last chunk should be OP_TRUE (0x51) selecting the IF branch.
    const lastChunk = chunks[chunks.length - 1]
    if (lastChunk.op !== OP.OP_TRUE && lastChunk.op !== OP.OP_1) {
      continue
    }

    // The preimage is the second-to-last element (before OP_TRUE).
    const preimageChunk = chunks[chunks.length - 2]
    if (preimageChunk.data == null || preimageChunk.data.length === 0) {
      continue
    }

    const preimage = Uint8Array.from(preimageChunk.data)

    // Verify hash if expected hash provided.
    if (expectedCapsuleHash != null) {
      const h = computeCapsuleHash(fileTxID ?? new Uint8Array(0), preimage)
      if (h == null || !timingSafeEqual(h, expectedCapsuleHash)) {
        continue // Hash mismatch - try next input.
      }
    }

    return preimage
  }

  throw new Error(`${ErrInvalidPreimage().message}: no HTLC preimage found in transaction inputs`)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Checks if a script binary is a standard P2PKH pattern:
 * OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
 */
function isP2PKH(scriptBin: number[]): boolean {
  // Standard P2PKH: 76 a9 14 <20 bytes> 88 ac = 25 bytes total
  if (scriptBin.length !== 25) return false
  return (
    scriptBin[0] === OP.OP_DUP &&
    scriptBin[1] === OP.OP_HASH160 &&
    scriptBin[2] === 0x14 && // Push 20 bytes
    scriptBin[23] === OP.OP_EQUALVERIFY &&
    scriptBin[24] === OP.OP_CHECKSIG
  )
}

/**
 * Extracts the 20-byte public key hash from a P2PKH script.
 */
function extractPKH(scriptBin: number[]): Uint8Array | null {
  if (!isP2PKH(scriptBin)) return null
  return Uint8Array.from(scriptBin.slice(3, 23))
}

/**
 * Decodes a base58check BSV address to its 20-byte public key hash.
 */
function addressToPKH(address: string): Uint8Array | null {
  try {
    const decoded = base58Decode(address)
    if (decoded == null || decoded.length !== 25) {
      return null
    }
    // Verify checksum: first 21 bytes -> double SHA256 -> first 4 bytes
    const payload = decoded.slice(0, 21)
    const checksum = decoded.slice(21, 25)
    const hash = Hash.hash256(Array.from(payload)) as number[]
    for (let i = 0; i < 4; i++) {
      if (hash[i] !== checksum[i]) return null
    }
    // Return the 20-byte PKH (skip version byte).
    return Uint8Array.from(payload.slice(1))
  } catch {
    return null
  }
}

/** Base58 alphabet. */
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

/** Decodes a base58 string to bytes. */
function base58Decode(str: string): Uint8Array | null {
  if (str.length === 0) return null

  // Count leading '1' characters (they represent leading zero bytes).
  let leadingZeros = 0
  for (let i = 0; i < str.length && str[i] === '1'; i++) {
    leadingZeros++
  }

  // Process the base58 string using bigint arithmetic.
  let num = 0n
  for (const char of str) {
    const idx = BASE58_ALPHABET.indexOf(char)
    if (idx === -1) return null
    num = num * 58n + BigInt(idx)
  }

  // Convert bigint to byte array.
  const bytes: number[] = []
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn))
    num >>= 8n
  }

  // Prepend leading zero bytes.
  const result = new Uint8Array(leadingZeros + bytes.length)
  // leading zeros are already 0 from Uint8Array init
  result.set(bytes, leadingZeros)

  return result
}

