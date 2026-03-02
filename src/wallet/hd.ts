/**
 * HD (Hierarchical Deterministic) wallet for BitFS.
 *
 * Key hierarchy: m/44'/236'/{account}'/{chain}/{index}[/filePath...]
 * - account 0: fee key chain
 * - account 1+: vaults (1-based, i.e. vaultIndex+1)
 *
 * Uses @bsv/sdk HD class for BIP32 derivation.
 */

import { HD, PrivateKey, PublicKey } from '@bsv/sdk'
import type { NetworkConfig } from './network.js'
import { MainNet } from './network.js'
import {
  InvalidSeedError,
  DerivationFailedError,
  FileIndexOutOfRangeError,
  PathTooDeepError,
} from './errors.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** BIP44 purpose field. */
export const PURPOSE_BIP44 = 44

/** BitFS coin type (registered). */
export const COIN_TYPE_BITFS = 236

/** BIP44 account index for fee keys. */
export const FEE_ACCOUNT = 0

/** First BIP44 account index used for vaults. */
export const DEFAULT_VAULT_ACCOUNT = 1

/** External (receive) chain index. */
export const EXTERNAL_CHAIN = 0

/** Internal (change) chain index. */
export const INTERNAL_CHAIN = 1

/** Maximum file index in non-hardened BIP32 range (2^31 - 1). */
export const MAX_FILE_INDEX = 0x7fffffff

/** Maximum filesystem nesting depth. */
export const MAX_PATH_DEPTH = 64

/** BIP32 hardened offset. */
export const HARDENED = 0x80000000

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A derived key pair with its human-readable path. */
export interface KeyPair {
  privateKey: PrivateKey
  publicKey: PublicKey
  path: string
}

// ---------------------------------------------------------------------------
// Wallet class
// ---------------------------------------------------------------------------

/**
 * HD wallet for BitFS key derivation.
 *
 * Wraps the @bsv/sdk HD class and provides BitFS-specific derivation paths.
 */
export class Wallet {
  private readonly masterKey: HD
  readonly network: NetworkConfig

  /**
   * Create a new Wallet from a BIP39 seed.
   *
   * @param seed - 64-byte BIP39 seed
   * @param network - Network configuration (defaults to MainNet)
   */
  constructor(seed: Uint8Array, network?: NetworkConfig) {
    if (seed.length === 0) {
      throw new InvalidSeedError()
    }

    this.network = network ?? MainNet

    try {
      this.masterKey = HD.fromSeed(Array.from(seed))
    } catch (e) {
      throw new DerivationFailedError(
        `master key creation: ${e instanceof Error ? e.message : String(e)}`,
      )
    }
  }

  /**
   * Derive the account-level key: m/44'/236'/account'
   */
  private deriveAccount(account: number): HD {
    try {
      return this.masterKey.derive(
        `m/${PURPOSE_BIP44}'/${COIN_TYPE_BITFS}'/${account}'`,
      )
    } catch (e) {
      throw new DerivationFailedError(
        `account derivation: ${e instanceof Error ? e.message : String(e)}`,
      )
    }
  }

  /**
   * Derive a key pair from the fee key chain.
   *
   * @param chain - EXTERNAL_CHAIN (0) for receive, INTERNAL_CHAIN (1) for change
   * @param index - Address index
   * @returns Derived key pair at path m/44'/236'/0'/chain/index
   */
  deriveFeeKey(chain: number, index: number): KeyPair {
    if (chain > 1) {
      throw new DerivationFailedError(`invalid chain ${chain} (must be 0 or 1)`)
    }

    const accountKey = this.deriveAccount(FEE_ACCOUNT)

    try {
      const childKey = accountKey.deriveChild(chain).deriveChild(index)
      const path = `m/44'/236'/0'/${chain}/${index}`
      return hdToKeyPair(childKey, path)
    } catch (e) {
      throw new DerivationFailedError(
        `fee key derivation: ${e instanceof Error ? e.message : String(e)}`,
      )
    }
  }

  /**
   * Derive the root key pair for a vault.
   *
   * @param vaultIndex - 0-based vault number
   * @returns Derived key pair at path m/44'/236'/(vaultIndex+1)'/0/0
   */
  deriveVaultRootKey(vaultIndex: number): KeyPair {
    return this.deriveNodeKey(vaultIndex)
  }

  /**
   * Derive a key pair for a filesystem node.
   *
   * @param vaultIndex - 0-based vault number
   * @param filePath - Sequence of child indices from root (e.g. [3, 1, 7])
   * @param hardened - Whether each index uses hardened derivation.
   *   null/undefined = all hardened (design decision #82).
   *   If shorter than filePath, remaining indices default to hardened.
   * @returns Derived key pair at path m/44'/236'/(vaultIndex+1)'/0/0[/filePath...]
   */
  deriveNodeKey(vaultIndex: number, filePath?: number[], hardened?: boolean[]): KeyPair {
    const path = filePath ?? []

    if (path.length > MAX_PATH_DEPTH) {
      throw new PathTooDeepError()
    }

    // Validate file indices
    for (const idx of path) {
      if (idx > MAX_FILE_INDEX) {
        throw new FileIndexOutOfRangeError()
      }
    }

    // Guard: accountIndex = vaultIndex + DEFAULT_VAULT_ACCOUNT must be < HARDENED
    if (vaultIndex >= HARDENED - DEFAULT_VAULT_ACCOUNT) {
      throw new FileIndexOutOfRangeError(
        `vault index ${vaultIndex} exceeds BIP32 hardened boundary`,
      )
    }

    const accountIndex = vaultIndex + DEFAULT_VAULT_ACCOUNT
    const accountKey = this.deriveAccount(accountIndex)

    try {
      // m/44'/236'/(V+1)'/0 (external chain)
      const chainKey = accountKey.deriveChild(EXTERNAL_CHAIN)

      // m/44'/236'/(V+1)'/0/0 (root directory)
      let current = chainKey.deriveChild(0)

      // Build human-readable path
      let pathStr = `m/44'/236'/${accountIndex}'/0/0`

      // Derive each level of the filesystem path
      for (let i = 0; i < path.length; i++) {
        const idx = path[i]

        // Default: hardened (design decision #82)
        let isHardened = true
        if (hardened != null && i < hardened.length) {
          isHardened = hardened[i]
        }

        if (isHardened) {
          current = current.deriveChild(idx + HARDENED)
          pathStr += `/${idx}'`
        } else {
          current = current.deriveChild(idx)
          pathStr += `/${idx}`
        }
      }

      return hdToKeyPair(current, pathStr)
    } catch (e) {
      // Re-throw our own errors as-is
      if (
        e instanceof PathTooDeepError ||
        e instanceof FileIndexOutOfRangeError ||
        e instanceof DerivationFailedError
      ) {
        throw e
      }
      throw new DerivationFailedError(
        `node key derivation: ${e instanceof Error ? e.message : String(e)}`,
      )
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Convert an HD key to a KeyPair.
 */
function hdToKeyPair(hd: HD, path: string): KeyPair {
  const privKey = hd.privKey
  if (!privKey) {
    throw new DerivationFailedError('failed to extract private key from HD node')
  }

  const pubKey = privKey.toPublicKey()
  if (!pubKey) {
    throw new DerivationFailedError('failed to derive public key')
  }

  return {
    privateKey: privKey,
    publicKey: pubKey,
    path,
  }
}
