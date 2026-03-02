import { BitfsError } from '../errors.js'

/** The mnemonic fails BIP39 validation. */
export class InvalidMnemonicError extends BitfsError {
  constructor() {
    super('wallet: invalid BIP39 mnemonic', 'WALLET_INVALID_MNEMONIC')
  }
}

/** Entropy bits is not 128 or 256. */
export class InvalidEntropyError extends BitfsError {
  constructor() {
    super('wallet: entropy bits must be 128 or 256', 'WALLET_INVALID_ENTROPY')
  }
}

/** A file index exceeds BIP32 non-hardened max (2^31-1). */
export class FileIndexOutOfRangeError extends BitfsError {
  constructor(detail?: string) {
    super(
      `wallet: file index exceeds maximum (2^31-1)${detail ? ': ' + detail : ''}`,
      'WALLET_FILE_INDEX_OUT_OF_RANGE',
    )
  }
}

/** Filesystem path exceeds maximum nesting depth (64). */
export class PathTooDeepError extends BitfsError {
  constructor() {
    super('wallet: path exceeds maximum depth (64)', 'WALLET_PATH_TOO_DEEP')
  }
}

/** The named vault does not exist. */
export class VaultNotFoundError extends BitfsError {
  constructor(name: string) {
    super(`wallet: vault not found: "${name}"`, 'WALLET_VAULT_NOT_FOUND')
  }
}

/** The vault name is already taken. */
export class VaultExistsError extends BitfsError {
  constructor(name: string) {
    super(`wallet: vault already exists: "${name}"`, 'WALLET_VAULT_EXISTS')
  }
}

/** Wrong password or corrupted wallet data. */
export class DecryptionFailedError extends BitfsError {
  constructor() {
    super(
      'wallet: seed decryption failed (wrong password or corrupted data)',
      'WALLET_DECRYPTION_FAILED',
    )
  }
}

/** Seed checksum verification failed after decryption. */
export class ChecksumMismatchError extends BitfsError {
  constructor() {
    super('wallet: seed checksum mismatch', 'WALLET_CHECKSUM_MISMATCH')
  }
}

/** Unknown network name with no custom config. */
export class InvalidNetworkError extends BitfsError {
  constructor(name: string) {
    super(`wallet: invalid network name: "${name}"`, 'WALLET_INVALID_NETWORK')
  }
}

/** The seed is empty or invalid. */
export class InvalidSeedError extends BitfsError {
  constructor() {
    super('wallet: invalid seed', 'WALLET_INVALID_SEED')
  }
}

/** BIP32 key derivation failed. */
export class DerivationFailedError extends BitfsError {
  constructor(detail?: string) {
    super(
      `wallet: key derivation failed${detail ? ': ' + detail : ''}`,
      'WALLET_DERIVATION_FAILED',
    )
  }
}

/** Vault limit reached: account index would exceed BIP32 hardened boundary. */
export class VaultLimitReachedError extends BitfsError {
  constructor() {
    super(
      'wallet: vault limit reached: account index would exceed BIP32 hardened boundary',
      'WALLET_VAULT_LIMIT_REACHED',
    )
  }
}

/** WalletState validation failed. */
export class WalletStateInvalidError extends BitfsError {
  constructor(detail: string) {
    super(`wallet: invalid state: ${detail}`, 'WALLET_STATE_INVALID')
  }
}
