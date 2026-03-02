import { BitfsError } from '../errors.js'

export class RevShareError extends BitfsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'RevShareError'
  }
}

export const ErrInvalidRegistryData = () => new RevShareError(
  'revshare: invalid registry data',
  'ERR_INVALID_REGISTRY_DATA',
)
export const ErrInvalidShareData = () => new RevShareError(
  'revshare: invalid share data',
  'ERR_INVALID_SHARE_DATA',
)
export const ErrInvalidISOPoolData = () => new RevShareError(
  'revshare: invalid ISO pool data',
  'ERR_INVALID_ISO_POOL_DATA',
)
export const ErrShareConservationViolation = () => new RevShareError(
  'revshare: share conservation violated',
  'ERR_SHARE_CONSERVATION_VIOLATION',
)
export const ErrNoEntries = () => new RevShareError(
  'revshare: no shareholder entries',
  'ERR_NO_ENTRIES',
)
export const ErrZeroTotalShares = () => new RevShareError(
  'revshare: zero total shares',
  'ERR_ZERO_TOTAL_SHARES',
)
export const ErrShareSumMismatch = () => new RevShareError(
  'revshare: sum of entry shares does not equal total shares',
  'ERR_SHARE_SUM_MISMATCH',
)
export const ErrOverflow = () => new RevShareError(
  'revshare: arithmetic overflow',
  'ERR_OVERFLOW',
)
export const ErrTooManyEntries = () => new RevShareError(
  'revshare: entry count exceeds uint32 max',
  'ERR_TOO_MANY_ENTRIES',
)
