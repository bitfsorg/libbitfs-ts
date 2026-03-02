import { BitfsError } from '../errors.js'

export class SpvError extends BitfsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'SpvError'
  }
}

/** Computed Merkle root does not match the expected root. */
export const ErrMerkleProofInvalid = () => new SpvError('spv: merkle proof invalid', 'ERR_MERKLE_PROOF_INVALID')

/** Block header not found in the local store. */
export const ErrHeaderNotFound = () => new SpvError('spv: header not found', 'ERR_HEADER_NOT_FOUND')

/** Transaction not found in the local store. */
export const ErrTxNotFound = () => new SpvError('spv: transaction not found', 'ERR_TX_NOT_FOUND')

/** Transaction has no Merkle proof (unconfirmed). */
export const ErrUnconfirmed = () => new SpvError('spv: transaction is unconfirmed', 'ERR_UNCONFIRMED')

/** Headers do not form a valid chain. */
export const ErrChainBroken = () => new SpvError('spv: header chain broken', 'ERR_CHAIN_BROKEN')

/** Header fails deserialization or hash check. */
export const ErrInvalidHeader = () => new SpvError('spv: invalid header', 'ERR_INVALID_HEADER')

/** Required parameter is null/undefined. */
export const ErrNilParam = () => new SpvError('spv: required parameter is nil', 'ERR_NIL_PARAM')

/** Transaction ID is not 32 bytes. */
export const ErrInvalidTxID = () => new SpvError('spv: invalid transaction ID', 'ERR_INVALID_TX_ID')

/** A header with this hash already exists in the store. */
export const ErrDuplicateHeader = () => new SpvError('spv: duplicate header', 'ERR_DUPLICATE_HEADER')

/** A transaction with this TxID already exists in the store. */
export const ErrDuplicateTx = () => new SpvError('spv: duplicate transaction', 'ERR_DUPLICATE_TX')

/** Header hash does not meet the target difficulty. */
export const ErrInsufficientPoW = () => new SpvError('spv: insufficient proof of work', 'ERR_INSUFFICIENT_POW')

/** Header's nBits target is below the network minimum. */
export const ErrDifficultyTooLow = () => new SpvError('spv: difficulty below network minimum', 'ERR_DIFFICULTY_TOO_LOW')

/** Header's nBits changed too much from the previous header. */
export const ErrDifficultyChange = () => new SpvError('spv: difficulty change exceeds allowed bounds', 'ERR_DIFFICULTY_CHANGE')
