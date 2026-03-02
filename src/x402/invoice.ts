import type { Invoice } from './types.js'
import { ErrInvalidParams } from './errors.js'
import { CAPSULE_HASH_LEN } from './types.js'

// ---------------------------------------------------------------------------
// Price calculation
// ---------------------------------------------------------------------------

/**
 * Computes the total price for content.
 *
 *   total = ceil(pricePerKB * fileSize / 1024)
 *
 * Returns 0n if either argument is 0n. Uses bigint arithmetic to avoid
 * overflow issues inherent with Number.
 */
export function calculatePrice(pricePerKB: bigint, fileSize: bigint): bigint {
  if (pricePerKB <= 0n || fileSize <= 0n) {
    return 0n
  }
  const numerator = pricePerKB * fileSize
  return (numerator + 1023n) / 1024n
}

// ---------------------------------------------------------------------------
// Invoice creation
// ---------------------------------------------------------------------------

/**
 * Creates a new payment invoice.
 *
 * @param pricePerKB  Unit price in satoshis per kilobyte.
 * @param fileSize    Content size in bytes.
 * @param paymentAddr BSV address where payment should be sent.
 * @param capsuleHash SHA256(capsule) for the HTLC hash lock (32 bytes).
 * @param ttlSeconds  Invoice time-to-live in seconds.
 * @returns A new Invoice.
 */
export function newInvoice(
  pricePerKB: bigint,
  fileSize: bigint,
  paymentAddr: string,
  capsuleHash: Uint8Array,
  ttlSeconds: number,
): Invoice {
  if (capsuleHash.length !== CAPSULE_HASH_LEN) {
    throw new Error(
      `${ErrInvalidParams.message}: capsule hash must be ${CAPSULE_HASH_LEN} bytes, got ${capsuleHash.length}`,
    )
  }
  if (!paymentAddr) {
    throw new Error(`${ErrInvalidParams.message}: payment address is required`)
  }
  if (ttlSeconds <= 0) {
    throw new Error(`${ErrInvalidParams.message}: ttlSeconds must be > 0`)
  }

  const id = generateInvoiceID()
  const totalPrice = calculatePrice(pricePerKB, fileSize)
  const now = Math.floor(Date.now() / 1000)

  return {
    id,
    price: totalPrice,
    pricePerKB,
    fileSize,
    paymentAddr,
    capsuleHash: new Uint8Array(capsuleHash),
    expiry: now + ttlSeconds,
  }
}

/**
 * Returns true if the invoice has passed its expiry time.
 */
export function isExpired(invoice: Invoice): boolean {
  return Math.floor(Date.now() / 1000) > invoice.expiry
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Generates a random 16-byte hex-encoded invoice ID.
 */
function generateInvoiceID(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return hexFromBytes(bytes)
}

/** Convert Uint8Array to hex string. */
function hexFromBytes(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}
