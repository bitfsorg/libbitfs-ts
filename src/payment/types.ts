import type { PrivateKey, PublicKey } from '@bsv/sdk'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Default HTLC refund timeout in blocks (~12 hours at ~10 min/block).
 * Balances security (seller has time to claim) with usability
 * (buyer's wallet does not need to stay online for an entire day).
 */
export const DEFAULT_HTLC_TIMEOUT = 72

/**
 * Minimum allowed HTLC timeout in blocks (~1 hour).
 * Setting the timeout too low risks the seller not having enough time to claim,
 * or the refund becoming broadcastable before the buyer receives the capsule.
 */
export const MIN_HTLC_TIMEOUT = 6

/**
 * Maximum allowed HTLC timeout in blocks (~2 days).
 * Excessively long timeouts force the buyer's wallet to remain online and keep
 * funds locked for an unreasonable duration.
 */
export const MAX_HTLC_TIMEOUT = 288

/** Expected length of a compressed public key. */
export const COMPRESSED_PUB_KEY_LEN = 33

/** Expected length of a P2PKH address hash. */
export const PUB_KEY_HASH_LEN = 20

/** Expected length of a capsule hash (SHA256). */
export const CAPSULE_HASH_LEN = 32

/** Expected length of an invoice ID for HTLC replay protection. */
export const INVOICE_ID_LEN = 16

/** Default fee rate in satoshis per byte. */
export const DEFAULT_HTLC_FEE_RATE = 1

// ---------------------------------------------------------------------------
// Invoice
// ---------------------------------------------------------------------------

/**
 * Invoice represents a payment request for content access.
 */
export interface Invoice {
  /** 16-byte random ID, hex-encoded (32 hex chars). */
  id: string
  /** Total price in satoshis. */
  price: bigint
  /** Unit price in satoshis per kilobyte. */
  pricePerKB: bigint
  /** Content size in bytes. */
  fileSize: bigint
  /** BSV address for payment. */
  paymentAddr: string
  /** SHA256(capsule) for HTLC hash lock (32 bytes). */
  capsuleHash: Uint8Array
  /** Unix timestamp of invoice expiry. */
  expiry: number
}

// ---------------------------------------------------------------------------
// HTLC
// ---------------------------------------------------------------------------

/**
 * HTLCParams holds parameters for creating an HTLC locking script.
 */
export interface HTLCParams {
  /** Buyer's compressed public key (33 bytes). */
  buyerPubKey: Uint8Array
  /** Seller's compressed public key (33 bytes). */
  sellerPubKey: Uint8Array
  /** Seller's P2PKH address hash (20 bytes). */
  sellerPubKeyHash: Uint8Array
  /** SHA256(capsule), 32 bytes. */
  capsuleHash: Uint8Array
  /** Payment amount in satoshis. */
  amount: bigint
  /** Refund timeout in blocks. Must be in [MIN_HTLC_TIMEOUT, MAX_HTLC_TIMEOUT]. */
  timeoutBlocks: number
  /** 16-byte invoice ID for replay protection (mandatory). */
  invoiceID: Uint8Array
}

/**
 * HTLCUTXO represents an unspent output for HTLC funding.
 */
export interface HTLCUTXO {
  /** 32 bytes, internal byte order. */
  txID: Uint8Array
  vout: number
  amount: bigint
  /** Locking script bytes. */
  scriptPubKey: Uint8Array
}

/**
 * HTLCFundingParams holds parameters for building an HTLC funding transaction.
 */
export interface HTLCFundingParams {
  /** Signs the P2PKH inputs. */
  buyerPrivKey: PrivateKey
  /** 20-byte P2PKH hash. */
  sellerPubKeyHash: Uint8Array
  /** 33-byte compressed public key (for HTLC script construction). */
  sellerPubKey: Uint8Array
  /** 32-byte SHA256(capsule). */
  capsuleHash: Uint8Array
  /** HTLC output satoshis. */
  amount: bigint
  /** Refund timeout in blocks (0 = DefaultHTLCTimeout). */
  timeout: number
  /** Buyer's unspent outputs. */
  utxos: HTLCUTXO[]
  /** 20-byte change address hash. */
  changeAddr: Uint8Array
  /** Satoshis per byte (0 = use default). */
  feeRate: number
  /** 16-byte invoice ID for replay protection (mandatory). */
  invoiceID: Uint8Array
}

/**
 * HTLCFundingResult holds the result of building an HTLC funding transaction.
 */
export interface HTLCFundingResult {
  /** Signed serialized transaction. */
  rawTx: Uint8Array
  /** 32-byte transaction hash. */
  txID: Uint8Array
  /** Index of the HTLC output. */
  htlcVout: number
  /** HTLC locking script bytes. */
  htlcScript: Uint8Array
  /** Actual HTLC output amount. */
  htlcAmount: bigint
}

/**
 * SellerClaimParams holds parameters for the seller claim transaction.
 */
export interface SellerClaimParams {
  /** 32-byte HTLC funding tx hash. */
  fundingTxID: Uint8Array
  /** HTLC output index in funding tx. */
  fundingVout: number
  /** HTLC output amount. */
  fundingAmount: bigint
  /** HTLC locking script bytes. */
  htlcScript: Uint8Array
  /** Preimage to reveal. */
  capsule: Uint8Array
  /** 32-byte file transaction ID (binds capsule hash to file identity). */
  fileTxID: Uint8Array
  /** Signs the claim. */
  sellerPrivKey: PrivateKey
  /** 20-byte destination P2PKH hash. */
  outputAddr: Uint8Array
  /** Satoshis per byte (0 = use default). */
  feeRate: number
}

// ---------------------------------------------------------------------------
// Payment headers
// ---------------------------------------------------------------------------

/**
 * PaymentHeaders holds the payment HTTP headers for a 402 response.
 */
export interface PaymentHeaders {
  price: bigint
  pricePerKB: bigint
  fileSize: bigint
  invoiceID: string
  expiry: number
}

// ---------------------------------------------------------------------------
// Payment proof
// ---------------------------------------------------------------------------

/**
 * PaymentProof represents a submitted payment for verification.
 */
export interface PaymentProof {
  /** Serialized BSV transaction. */
  rawTx: Uint8Array
  /** Invoice ID for tracking. */
  invoiceID: Uint8Array
}

// ---------------------------------------------------------------------------
// Refund (on-chain buyer-only via nLockTime)
// ---------------------------------------------------------------------------

/**
 * BuyerRefundParams holds parameters for building an on-chain refund transaction.
 * The buyer can refund unilaterally after the timeout -- no seller cooperation needed.
 * The timeout is enforced at the transaction level via nLockTime (not in the
 * script — BSV post-Genesis treats OP_CLTV as OP_NOP2).
 */
export interface BuyerRefundParams {
  /** 32-byte HTLC funding tx hash. */
  fundingTxID: Uint8Array
  /** HTLC output index in funding tx. */
  fundingVout: number
  /** HTLC output amount. */
  fundingAmount: bigint
  /** HTLC locking script bytes. */
  htlcScript: Uint8Array
  /** Signs the refund. */
  buyerPrivKey: PrivateKey
  /** 20-byte destination P2PKH hash. */
  outputAddr: Uint8Array
  /** Block height for nLockTime (0 = DefaultHTLCTimeout). */
  timeout: number
  /** Satoshis per byte (0 = use default). */
  feeRate?: number
}
