/**
 * BitFS tx module.
 *
 * UTXO types, OP_RETURN builder/parser, fee estimation,
 * MutationBatch for atomic multi-op transaction building, and signing.
 */

// Errors
export {
  NilParamError,
  InsufficientFundsError,
  InvalidPayloadError,
  InvalidParentTxIDError,
  SigningFailedError,
  ScriptBuildError,
  InvalidOPReturnError,
  NotMetanetTxError,
  InvalidParamsError,
} from './errors.js'

// Types
export type {
  UTXO,
  BatchNodeOp,
  BatchResult,
  BatchNodeResult,
} from './types.js'
export { BatchOpType } from './types.js'

// OP_RETURN builder/parser + constants
export {
  META_FLAG,
  DUST_LIMIT,
  DEFAULT_FEE_RATE,
  COMPRESSED_PUB_KEY_LEN,
  TXID_LEN,
  buildOPReturnData,
  parseOPReturnData,
  estimateFee,
  estimateTxSize,
} from './opreturn.js'

// Script builders + signing
export {
  buildP2PKHLockingScript,
  buildP2PKHFromHash,
  buildOPReturnScript,
  signBatchResult,
} from './sign.js'

// MutationBatch
export { MutationBatch } from './batch.js'
