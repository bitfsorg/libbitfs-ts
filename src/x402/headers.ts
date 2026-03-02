import type { PaymentHeaders, Invoice } from './types.js'
import { ErrMissingHeaders } from './errors.js'

// ---------------------------------------------------------------------------
// x402 HTTP header names
// ---------------------------------------------------------------------------

export const HEADER_PRICE = 'X-Price'
export const HEADER_PRICE_PER_KB = 'X-Price-Per-KB'
export const HEADER_FILE_SIZE = 'X-File-Size'
export const HEADER_INVOICE_ID = 'X-Invoice-Id'
export const HEADER_EXPIRY = 'X-Expiry'

// ---------------------------------------------------------------------------
// Parse / Create payment headers
// ---------------------------------------------------------------------------

/**
 * Extracts x402 headers from a Headers object (browser Fetch API style).
 *
 * All five headers (X-Price, X-Price-Per-KB, X-File-Size, X-Invoice-Id,
 * X-Expiry) are required. Missing or invalid values throw an error.
 */
export function parsePaymentHeaders(headers: Headers): PaymentHeaders {
  const priceStr = headers.get(HEADER_PRICE)
  if (priceStr == null || priceStr === '') {
    throw new Error(`${ErrMissingHeaders.message}: ${HEADER_PRICE} header missing`)
  }
  const price = parseBigInt(priceStr, HEADER_PRICE)

  const pricePerKBStr = headers.get(HEADER_PRICE_PER_KB)
  if (pricePerKBStr == null || pricePerKBStr === '') {
    throw new Error(`${ErrMissingHeaders.message}: ${HEADER_PRICE_PER_KB} header missing`)
  }
  const pricePerKB = parseBigInt(pricePerKBStr, HEADER_PRICE_PER_KB)

  const fileSizeStr = headers.get(HEADER_FILE_SIZE)
  if (fileSizeStr == null || fileSizeStr === '') {
    throw new Error(`${ErrMissingHeaders.message}: ${HEADER_FILE_SIZE} header missing`)
  }
  const fileSize = parseBigInt(fileSizeStr, HEADER_FILE_SIZE)

  const invoiceID = headers.get(HEADER_INVOICE_ID)
  if (invoiceID == null || invoiceID === '') {
    throw new Error(`${ErrMissingHeaders.message}: ${HEADER_INVOICE_ID} header missing`)
  }

  const expiryStr = headers.get(HEADER_EXPIRY)
  if (expiryStr == null || expiryStr === '') {
    throw new Error(`${ErrMissingHeaders.message}: ${HEADER_EXPIRY} header missing`)
  }
  const expiry = parseIntStrict(expiryStr, HEADER_EXPIRY)

  return {
    price,
    pricePerKB,
    fileSize,
    invoiceID,
    expiry,
  }
}

/**
 * Creates PaymentHeaders from an Invoice.
 */
export function paymentHeadersFromInvoice(inv: Invoice): PaymentHeaders {
  return {
    price: inv.price,
    pricePerKB: inv.pricePerKB,
    fileSize: inv.fileSize,
    invoiceID: inv.id,
    expiry: inv.expiry,
  }
}

/**
 * Converts PaymentHeaders to a Headers object (browser Fetch API style).
 */
export function paymentHeadersToHeaders(ph: PaymentHeaders): Headers {
  const headers = new Headers()
  headers.set(HEADER_PRICE, ph.price.toString())
  headers.set(HEADER_PRICE_PER_KB, ph.pricePerKB.toString())
  headers.set(HEADER_FILE_SIZE, ph.fileSize.toString())
  headers.set(HEADER_INVOICE_ID, ph.invoiceID)
  headers.set(HEADER_EXPIRY, ph.expiry.toString())
  return headers
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function parseBigInt(value: string, headerName: string): bigint {
  try {
    const n = BigInt(value)
    if (n < 0n) {
      throw new Error('negative')
    }
    return n
  } catch {
    throw new Error(`${ErrMissingHeaders.message}: invalid ${headerName} value: ${value}`)
  }
}

function parseIntStrict(value: string, headerName: string): number {
  const n = Number(value)
  if (!Number.isFinite(n) || n !== Math.floor(n)) {
    throw new Error(`${ErrMissingHeaders.message}: invalid ${headerName} value: ${value}`)
  }
  return n
}
