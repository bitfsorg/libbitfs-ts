// payment — HTTP 402 Payment Required protocol for BitFS

// Errors
export {
  PaymentError,
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
  BuyerRefundParams,
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

// Artifact (sCrypt compiled contract)
export { loadArtifact, instantiateHTLC, isArtifactScript, encodeScryptInt } from './artifact.js'
export type { Artifact, ABIEntity } from './artifact.js'
export {
  HTLC_INVOICE_ID_OFFSET,
  HTLC_CAPSULE_HASH_OFFSET,
  HTLC_SELLER_PKH_OFFSET,
  HTLC_BUYER_PKH_OFFSET,
  HTLC_MIN_SCRIPT_LEN,
} from './artifact.js'

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

// Refund (on-chain buyer-only via OP_PUSH_TX + nLockTime)
export {
  verifyHTLCFunding,
  buildBuyerRefundTx,
} from './refund.js'

// Verification
export { verifyPayment, parseHTLCPreimage } from './verify.js'
