import { BitfsError } from '../errors.js'

/** A required parameter is null or undefined. */
export class NilParamError extends BitfsError {
  constructor(message: string) {
    super(message, 'TX_NIL_PARAM')
  }
}

/** The fee UTXO cannot cover fees and dust outputs. */
export class InsufficientFundsError extends BitfsError {
  constructor(need: bigint, have: bigint) {
    super(`insufficient funds: need ${need} sat, have ${have} sat`, 'TX_INSUFFICIENT_FUNDS')
  }
}

/** The payload is empty or exceeds limits. */
export class InvalidPayloadError extends BitfsError {
  constructor(message: string) {
    super(message, 'TX_INVALID_PAYLOAD')
  }
}

/** Parent TxID is not 0 or 32 bytes. */
export class InvalidParentTxIDError extends BitfsError {
  constructor(length: number) {
    super(`parent TxID must be 0 or 32 bytes, got ${length}`, 'TX_INVALID_PARENT_TXID')
  }
}

/** Transaction signing failed. */
export class SigningFailedError extends BitfsError {
  constructor(message: string) {
    super(message, 'TX_SIGNING_FAILED')
  }
}

/** Script construction failed. */
export class ScriptBuildError extends BitfsError {
  constructor(message: string) {
    super(message, 'TX_SCRIPT_BUILD')
  }
}

/** The OP_RETURN script is malformed. */
export class InvalidOPReturnError extends BitfsError {
  constructor(message: string) {
    super(message, 'TX_INVALID_OP_RETURN')
  }
}

/** The transaction is not a valid Metanet transaction. */
export class NotMetanetTxError extends BitfsError {
  constructor() {
    super('not a Metanet transaction', 'TX_NOT_METANET')
  }
}

/** Invalid parameters were provided. */
export class InvalidParamsError extends BitfsError {
  constructor(message: string) {
    super(message, 'TX_INVALID_PARAMS')
  }
}
