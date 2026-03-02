// x402 — HTTP 402 Payment Required protocol for BitFS

// Errors
export {
  X402Error,
  ErrInvoiceExpired,
  ErrInsufficientPayment,
  ErrPaymentAddrMismatch,
  ErrInvalidTx,
  ErrHTLCBuildFailed,
  ErrNoMatchingOutput,
  ErrInvalidParams,
  ErrInvalidPreimage,
  ErrMissingHeaders,
  ErrFundingMismatch,
} from './errors.js'

// Types & constants
export type {
  Invoice,
  HTLCParams,
  HTLCUTXO,
  HTLCFundingParams,
  HTLCFundingResult,
  SellerClaimParams,
  PaymentHeaders,
  PaymentProof,
} from './types.js'
export {
  DEFAULT_HTLC_TIMEOUT,
  MIN_HTLC_TIMEOUT,
  MAX_HTLC_TIMEOUT,
  COMPRESSED_PUB_KEY_LEN,
  PUB_KEY_HASH_LEN,
  CAPSULE_HASH_LEN,
  INVOICE_ID_LEN,
  DEFAULT_HTLC_FEE_RATE,
} from './types.js'

// Invoice
export { calculatePrice, newInvoice, isExpired } from './invoice.js'

// HTLC script + transactions
export {
  buildHTLC,
  extractCapsuleHashFromHTLC,
  extractInvoiceIDFromHTLC,
  buildHTLCFundingTx,
  buildSellerClaimTx,
} from './htlc.js'

// Payment headers
export {
  HEADER_PRICE,
  HEADER_PRICE_PER_KB,
  HEADER_FILE_SIZE,
  HEADER_INVOICE_ID,
  HEADER_EXPIRY,
  parsePaymentHeaders,
  paymentHeadersFromInvoice,
  paymentHeadersToHeaders,
} from './headers.js'

// Verification
export { verifyPayment, parseHTLCPreimage } from './verify.js'
