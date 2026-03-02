/**
 * BitFS wallet module.
 *
 * BIP39 mnemonic, BIP32 HD key derivation, seed encryption, vault management,
 * and network configuration.
 */

// Errors
export {
  InvalidMnemonicError,
  InvalidEntropyError,
  InvalidSeedError,
  InvalidNetworkError,
  DecryptionFailedError,
  ChecksumMismatchError,
  DerivationFailedError,
  FileIndexOutOfRangeError,
  PathTooDeepError,
  VaultExistsError,
  VaultNotFoundError,
  VaultLimitReachedError,
  WalletStateInvalidError,
} from './errors.js'

// Seed: mnemonic, seed derivation, encryption
export {
  generateMnemonic,
  validateMnemonic,
  seedFromMnemonic,
  encryptSeed,
  decryptSeed,
  MNEMONIC_12_WORDS,
  MNEMONIC_24_WORDS,
  ARGON2_TIME,
  ARGON2_MEMORY,
  ARGON2_PARALLELISM,
  ARGON2_KEY_LEN,
  SALT_LEN,
  NONCE_LEN,
  CHECKSUM_LEN,
} from './seed.js'

// Network configurations
export type { NetworkConfig } from './network.js'
export { MainNet, TestNet, RegTest, getNetwork } from './network.js'

// HD wallet and key derivation
export type { KeyPair } from './hd.js'
export {
  Wallet,
  PURPOSE_BIP44,
  COIN_TYPE_BITFS,
  FEE_ACCOUNT,
  DEFAULT_VAULT_ACCOUNT,
  EXTERNAL_CHAIN,
  INTERNAL_CHAIN,
  MAX_FILE_INDEX,
  MAX_PATH_DEPTH,
  HARDENED,
} from './hd.js'

// Vault management
export type { Vault, WalletState } from './vault.js'
export {
  newWalletState,
  createVault,
  getVault,
  listVaults,
  renameVault,
  deleteVault,
  validateWalletState,
} from './vault.js'
