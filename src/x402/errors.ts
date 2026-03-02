import { BitfsError } from '../errors.js'

export class X402Error extends BitfsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'X402Error'
  }
}

export const ErrInvoiceExpired = new X402Error('invoice expired', 'ERR_INVOICE_EXPIRED')
export const ErrInsufficientPayment = new X402Error('insufficient payment amount', 'ERR_INSUFFICIENT_PAYMENT')
export const ErrPaymentAddrMismatch = new X402Error('payment address mismatch', 'ERR_PAYMENT_ADDR_MISMATCH')
export const ErrInvalidTx = new X402Error('invalid transaction', 'ERR_INVALID_TX')
export const ErrHTLCBuildFailed = new X402Error('HTLC script build failed', 'ERR_HTLC_BUILD_FAILED')
export const ErrNoMatchingOutput = new X402Error('no matching output found', 'ERR_NO_MATCHING_OUTPUT')
export const ErrInvalidParams = new X402Error('invalid parameters', 'ERR_INVALID_PARAMS')
export const ErrInvalidPreimage = new X402Error('invalid HTLC preimage', 'ERR_INVALID_PREIMAGE')
export const ErrMissingHeaders = new X402Error('missing payment headers', 'ERR_MISSING_HEADERS')
export const ErrFundingMismatch = new X402Error('funding UTXO mismatch', 'ERR_FUNDING_MISMATCH')
