// revshare — revenue distribution + serialization for BitFS

// Errors
export {
  RevShareError,
  ErrInvalidRegistryData,
  ErrInvalidShareData,
  ErrInvalidISOPoolData,
  ErrShareConservationViolation,
  ErrNoEntries,
  ErrZeroTotalShares,
  ErrShareSumMismatch,
  ErrOverflow,
  ErrTooManyEntries,
} from './errors.js'

// Types
export type {
  RevShareEntry,
  RegistryState,
  ShareData,
  ISOPoolState,
  Distribution,
} from './types.js'
export { isISOActive, isLocked, findEntry } from './types.js'

// Distribution
export { distributeRevenue, validateShareConservation } from './distribute.js'

// Serialization
export {
  serializeRegistry,
  deserializeRegistry,
  serializeShare,
  deserializeShare,
  serializeISOPool,
  deserializeISOPool,
} from './serialize.js'
