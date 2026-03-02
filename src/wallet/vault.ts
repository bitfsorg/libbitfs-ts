/**
 * Vault management for the BitFS wallet.
 *
 * Each Vault represents an independent Metanet directory tree,
 * corresponding to one BIP32 account (1-based for vaults).
 *
 * Vault state is a simple in-memory structure; persistence is the
 * caller's responsibility.
 */

import { HARDENED, DEFAULT_VAULT_ACCOUNT } from './hd.js'
import {
  VaultExistsError,
  VaultNotFoundError,
  VaultLimitReachedError,
  WalletStateInvalidError,
} from './errors.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** An independent Metanet directory tree. */
export interface Vault {
  /** Human-readable name. */
  name: string
  /** BIP44 account index (0-based vault index). */
  accountIndex: number
  /** Root node transaction ID (null if unpublished). */
  rootTxID: Uint8Array | null
  /** Soft-deleted flag. */
  deleted: boolean
}

/** Persisted wallet metadata. */
export interface WalletState {
  /** Fee chain next receive address index. */
  nextReceiveIndex: number
  /** Fee chain next change address index. */
  nextChangeIndex: number
  /** All vaults (including soft-deleted ones). */
  vaults: Vault[]
  /** Next available vault account index. */
  nextVaultIndex: number
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a new empty WalletState.
 */
export function newWalletState(): WalletState {
  return {
    nextReceiveIndex: 0,
    nextChangeIndex: 0,
    vaults: [],
    nextVaultIndex: 0,
  }
}

// ---------------------------------------------------------------------------
// Vault CRUD
// ---------------------------------------------------------------------------

/**
 * Create a new vault with the given name.
 *
 * Allocates the next available account index (0-based vault index,
 * which maps to BIP44 account index = vaultIndex + 1).
 *
 * @param state - Wallet state to mutate
 * @param name - Vault name
 * @returns The newly created Vault
 */
export function createVault(state: WalletState, name: string): Vault {
  // Guard: next vault index must stay below Hardened boundary
  if (state.nextVaultIndex >= HARDENED - DEFAULT_VAULT_ACCOUNT) {
    throw new VaultLimitReachedError()
  }

  // Check for duplicate names among active vaults
  for (const v of state.vaults) {
    if (v.name === name && !v.deleted) {
      throw new VaultExistsError(name)
    }
  }

  const vault: Vault = {
    name,
    accountIndex: state.nextVaultIndex,
    rootTxID: null,
    deleted: false,
  }

  state.vaults.push(vault)
  state.nextVaultIndex++

  return vault
}

/**
 * Retrieve a vault by name. Only returns active (non-deleted) vaults.
 *
 * @param state - Wallet state to search
 * @param name - Vault name
 * @returns The found Vault
 * @throws VaultNotFoundError if the vault does not exist
 */
export function getVault(state: WalletState, name: string): Vault {
  for (const v of state.vaults) {
    if (v.name === name && !v.deleted) {
      return v
    }
  }
  throw new VaultNotFoundError(name)
}

/**
 * List all active (non-deleted) vaults.
 *
 * @param state - Wallet state to search
 * @returns Array of active Vaults
 */
export function listVaults(state: WalletState): Vault[] {
  return state.vaults.filter((v) => !v.deleted)
}

/**
 * Rename an existing vault.
 *
 * @param state - Wallet state to mutate
 * @param oldName - Current vault name
 * @param newName - New vault name
 * @throws VaultExistsError if the new name is already taken
 * @throws VaultNotFoundError if the old name does not exist
 */
export function renameVault(state: WalletState, oldName: string, newName: string): void {
  // Check new name doesn't conflict
  for (const v of state.vaults) {
    if (v.name === newName && !v.deleted) {
      throw new VaultExistsError(newName)
    }
  }

  for (const v of state.vaults) {
    if (v.name === oldName && !v.deleted) {
      v.name = newName
      return
    }
  }
  throw new VaultNotFoundError(oldName)
}

/**
 * Mark a vault as deleted (soft delete).
 *
 * The account index is never reused.
 *
 * @param state - Wallet state to mutate
 * @param name - Vault name to delete
 * @throws VaultNotFoundError if the vault does not exist
 */
export function deleteVault(state: WalletState, name: string): void {
  for (const v of state.vaults) {
    if (v.name === name && !v.deleted) {
      v.deleted = true
      return
    }
  }
  throw new VaultNotFoundError(name)
}

/**
 * Validate the integrity of a WalletState.
 *
 * Checks for:
 * - Account index within BIP32 range
 * - Duplicate account indices among active vaults
 * - NextVaultIndex consistency with existing vaults
 *
 * @param state - Wallet state to validate
 * @throws WalletStateInvalidError if validation fails
 */
export function validateWalletState(state: WalletState): void {
  const seen = new Map<number, string>()
  let maxIdx = 0

  for (const v of state.vaults) {
    if (v.deleted) continue

    // Check account index within BIP32 range
    if (v.accountIndex >= HARDENED - DEFAULT_VAULT_ACCOUNT) {
      throw new WalletStateInvalidError(
        `vault "${v.name}": account index ${v.accountIndex} exceeds BIP32 hardened boundary`,
      )
    }

    // Check for duplicate account indices among active vaults
    const prev = seen.get(v.accountIndex)
    if (prev !== undefined) {
      throw new WalletStateInvalidError(
        `duplicate account index ${v.accountIndex}: vaults "${prev}" and "${v.name}"`,
      )
    }
    seen.set(v.accountIndex, v.name)

    if (v.accountIndex >= maxIdx) {
      maxIdx = v.accountIndex + 1
    }
  }

  // NextVaultIndex must be >= max seen index + 1 (to avoid reuse)
  if (seen.size > 0 && state.nextVaultIndex < maxIdx) {
    throw new WalletStateInvalidError(
      `NextVaultIndex (${state.nextVaultIndex}) is less than max account index + 1 (${maxIdx})`,
    )
  }
}
