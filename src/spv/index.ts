// spv — Block headers, Merkle proofs, and SPV verification for BitFS

// Errors
export {
  SpvError,
  ErrMerkleProofInvalid,
  ErrHeaderNotFound,
  ErrTxNotFound,
  ErrUnconfirmed,
  ErrChainBroken,
  ErrInvalidHeader,
  ErrNilParam,
  ErrInvalidTxID,
  ErrDuplicateHeader,
  ErrDuplicateTx,
  ErrInsufficientPoW,
  ErrDifficultyTooLow,
  ErrDifficultyChange,
} from './errors.js'

// Types
export {
  BLOCK_HEADER_SIZE,
  HASH_SIZE,
  Network,
} from './types.js'
export type {
  BlockHeader,
  MerkleProof,
  StoredTx,
  HeaderStore,
  TxStore,
} from './types.js'

// Merkle tree
export {
  doubleHash,
  computeMerkleRoot,
  verifyMerkleProof,
  buildMerkleTree,
  computeMerkleRootFromTxList,
} from './merkle.js'

// Header serialization, PoW, chain verification
export {
  MAINNET_MIN_BITS,
  TESTNET_MIN_BITS,
  REGTEST_MIN_BITS,
  serializeHeader,
  deserializeHeader,
  computeHeaderHash,
  compactToTarget,
  compactToBigInt,
  workForTarget,
  cumulativeWork,
  verifyPoW,
  minBitsForNetwork,
  validateMinDifficulty,
  validateDifficultyTransition,
  verifyHeaderChain,
  verifyHeaderChainWithWork,
} from './header.js'
export type { ChainVerificationResult } from './header.js'

// In-memory stores
export { MemHeaderStore, MemTxStore } from './store.js'

// SPV verification
export { verifyTransaction, verifyTransactionWithNetwork } from './verify.js'
