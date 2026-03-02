import { describe, it, expect } from 'vitest'
import {
  newWalletState,
  createVault,
  getVault,
  listVaults,
  renameVault,
  deleteVault,
  validateWalletState,
  HARDENED,
  DEFAULT_VAULT_ACCOUNT,
  VaultExistsError,
  VaultNotFoundError,
  VaultLimitReachedError,
  WalletStateInvalidError,
} from '../index.js'
import type { WalletState, Vault } from '../index.js'

// ---------------------------------------------------------------------------
// newWalletState
// ---------------------------------------------------------------------------

describe('newWalletState', () => {
  it('creates an empty state with correct defaults', () => {
    const state = newWalletState()
    expect(state.nextReceiveIndex).toBe(0)
    expect(state.nextChangeIndex).toBe(0)
    expect(state.vaults).toEqual([])
    expect(state.nextVaultIndex).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// createVault
// ---------------------------------------------------------------------------

describe('createVault', () => {
  it('creates a vault with correct initial values', () => {
    const state = newWalletState()
    const vault = createVault(state, 'personal')
    expect(vault.name).toBe('personal')
    expect(vault.accountIndex).toBe(0)
    expect(vault.rootTxID).toBeNull()
    expect(vault.deleted).toBe(false)
    expect(state.vaults).toHaveLength(1)
    expect(state.nextVaultIndex).toBe(1)
  })

  it('creates multiple vaults with sequential indices', () => {
    const state = newWalletState()
    const v1 = createVault(state, 'personal')
    const v2 = createVault(state, 'company')
    expect(v1.accountIndex).toBe(0)
    expect(v2.accountIndex).toBe(1)
    expect(state.vaults).toHaveLength(2)
  })

  it('throws VaultExistsError for duplicate name', () => {
    const state = newWalletState()
    createVault(state, 'personal')
    expect(() => createVault(state, 'personal')).toThrow(VaultExistsError)
  })

  it('allows reusing name of a deleted vault', () => {
    const state = newWalletState()
    createVault(state, 'temp')
    deleteVault(state, 'temp')

    const vault = createVault(state, 'temp')
    expect(vault.name).toBe('temp')
    // Account index is never reused
    expect(vault.accountIndex).toBe(1)
  })

  it('allows empty string name', () => {
    const state = newWalletState()
    const vault = createVault(state, '')
    expect(vault.name).toBe('')

    const v = getVault(state, '')
    expect(v.name).toBe('')
  })

  it('throws VaultLimitReachedError at HARDENED boundary', () => {
    const state = newWalletState()
    state.nextVaultIndex = HARDENED - 1
    expect(() => createVault(state, 'overflow')).toThrow(VaultLimitReachedError)
  })
})

// ---------------------------------------------------------------------------
// getVault
// ---------------------------------------------------------------------------

describe('getVault', () => {
  it('retrieves an existing vault', () => {
    const state = newWalletState()
    createVault(state, 'personal')
    const vault = getVault(state, 'personal')
    expect(vault.name).toBe('personal')
  })

  it('throws VaultNotFoundError for nonexistent vault', () => {
    const state = newWalletState()
    expect(() => getVault(state, 'nonexistent')).toThrow(VaultNotFoundError)
  })

  it('does not return deleted vaults', () => {
    const state = newWalletState()
    createVault(state, 'personal')
    deleteVault(state, 'personal')
    expect(() => getVault(state, 'personal')).toThrow(VaultNotFoundError)
  })
})

// ---------------------------------------------------------------------------
// listVaults
// ---------------------------------------------------------------------------

describe('listVaults', () => {
  it('lists all active vaults', () => {
    const state = newWalletState()
    createVault(state, 'personal')
    createVault(state, 'company')
    const vaults = listVaults(state)
    expect(vaults).toHaveLength(2)
  })

  it('excludes deleted vaults', () => {
    const state = newWalletState()
    createVault(state, 'personal')
    createVault(state, 'company')
    deleteVault(state, 'company')
    const vaults = listVaults(state)
    expect(vaults).toHaveLength(1)
    expect(vaults[0].name).toBe('personal')
  })

  it('returns empty array for empty state', () => {
    const state = newWalletState()
    expect(listVaults(state)).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// renameVault
// ---------------------------------------------------------------------------

describe('renameVault', () => {
  it('renames an existing vault', () => {
    const state = newWalletState()
    createVault(state, 'old-name')
    renameVault(state, 'old-name', 'new-name')

    expect(() => getVault(state, 'old-name')).toThrow(VaultNotFoundError)
    const vault = getVault(state, 'new-name')
    expect(vault.name).toBe('new-name')
  })

  it('throws VaultExistsError when new name conflicts', () => {
    const state = newWalletState()
    createVault(state, 'a')
    createVault(state, 'b')
    expect(() => renameVault(state, 'a', 'b')).toThrow(VaultExistsError)
  })

  it('throws VaultNotFoundError for nonexistent old name', () => {
    const state = newWalletState()
    expect(() => renameVault(state, 'does-not-exist', 'new-name')).toThrow(
      VaultNotFoundError,
    )
  })
})

// ---------------------------------------------------------------------------
// deleteVault
// ---------------------------------------------------------------------------

describe('deleteVault', () => {
  it('soft-deletes a vault', () => {
    const state = newWalletState()
    createVault(state, 'personal')
    deleteVault(state, 'personal')
    expect(() => getVault(state, 'personal')).toThrow(VaultNotFoundError)
    // The vault is still in the array but marked deleted
    expect(state.vaults).toHaveLength(1)
    expect(state.vaults[0].deleted).toBe(true)
  })

  it('throws VaultNotFoundError for nonexistent vault', () => {
    const state = newWalletState()
    expect(() => deleteVault(state, 'nonexistent')).toThrow(VaultNotFoundError)
  })
})

// ---------------------------------------------------------------------------
// validateWalletState
// ---------------------------------------------------------------------------

describe('validateWalletState', () => {
  it('accepts valid empty state', () => {
    expect(() => validateWalletState(newWalletState())).not.toThrow()
  })

  it('accepts valid state with vault', () => {
    const state: WalletState = {
      nextReceiveIndex: 0,
      nextChangeIndex: 0,
      vaults: [{ name: 'v0', accountIndex: 0, rootTxID: null, deleted: false }],
      nextVaultIndex: 1,
    }
    expect(() => validateWalletState(state)).not.toThrow()
  })

  it('rejects NextVaultIndex too low', () => {
    const state: WalletState = {
      nextReceiveIndex: 0,
      nextChangeIndex: 0,
      vaults: [{ name: 'v0', accountIndex: 5, rootTxID: null, deleted: false }],
      nextVaultIndex: 3,
    }
    expect(() => validateWalletState(state)).toThrow(WalletStateInvalidError)
    expect(() => validateWalletState(state)).toThrow(/NextVaultIndex/)
  })

  it('rejects duplicate account index', () => {
    const state: WalletState = {
      nextReceiveIndex: 0,
      nextChangeIndex: 0,
      vaults: [
        { name: 'a', accountIndex: 0, rootTxID: null, deleted: false },
        { name: 'b', accountIndex: 0, rootTxID: null, deleted: false },
      ],
      nextVaultIndex: 1,
    }
    expect(() => validateWalletState(state)).toThrow(WalletStateInvalidError)
    expect(() => validateWalletState(state)).toThrow(/duplicate/)
  })

  it('rejects account index at HARDENED boundary', () => {
    const state: WalletState = {
      nextReceiveIndex: 0,
      nextChangeIndex: 0,
      vaults: [
        {
          name: 'v0',
          accountIndex: HARDENED - 1,
          rootTxID: null,
          deleted: false,
        },
      ],
      nextVaultIndex: HARDENED,
    }
    expect(() => validateWalletState(state)).toThrow(WalletStateInvalidError)
    expect(() => validateWalletState(state)).toThrow(/exceeds/)
  })

  it('ignores deleted vaults in validation', () => {
    const state: WalletState = {
      nextReceiveIndex: 0,
      nextChangeIndex: 0,
      vaults: [
        { name: 'a', accountIndex: 0, rootTxID: null, deleted: true },
        { name: 'b', accountIndex: 0, rootTxID: null, deleted: true },
      ],
      nextVaultIndex: 0,
    }
    // Both have same accountIndex but are deleted, so no error
    expect(() => validateWalletState(state)).not.toThrow()
  })
})
