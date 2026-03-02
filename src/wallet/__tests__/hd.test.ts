import { describe, it, expect } from 'vitest'
import {
  Wallet,
  seedFromMnemonic,
  MainNet,
  TestNet,
  EXTERNAL_CHAIN,
  INTERNAL_CHAIN,
  MAX_PATH_DEPTH,
  MAX_FILE_INDEX,
  HARDENED,
  InvalidSeedError,
  DerivationFailedError,
  PathTooDeepError,
  FileIndexOutOfRangeError,
} from '../index.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

function newTestWallet(network = MainNet): Wallet {
  const seed = seedFromMnemonic(TEST_MNEMONIC, '')
  return new Wallet(seed, network)
}

function pubKeyHex(w: Wallet, fn: () => ReturnType<Wallet['deriveFeeKey']>): string {
  const kp = fn.call(w)
  return kp.publicKey.toDER('hex') as string
}

// ---------------------------------------------------------------------------
// Wallet construction
// ---------------------------------------------------------------------------

describe('Wallet constructor', () => {
  it('creates a wallet with mainnet default', () => {
    const w = newTestWallet()
    expect(w.network.name).toBe('mainnet')
  })

  it('creates a wallet with specified network', () => {
    const w = newTestWallet(TestNet)
    expect(w.network.name).toBe('testnet')
  })

  it('defaults to mainnet when network is undefined', () => {
    const seed = seedFromMnemonic(TEST_MNEMONIC, '')
    const w = new Wallet(seed)
    expect(w.network.name).toBe('mainnet')
  })

  it('throws InvalidSeedError for empty seed', () => {
    expect(() => new Wallet(new Uint8Array(0))).toThrow(InvalidSeedError)
  })
})

// ---------------------------------------------------------------------------
// Fee key derivation
// ---------------------------------------------------------------------------

describe('deriveFeeKey', () => {
  it('derives receive key at m/44\'/236\'/0\'/0/0', () => {
    const w = newTestWallet()
    const kp = w.deriveFeeKey(EXTERNAL_CHAIN, 0)
    expect(kp.privateKey).toBeDefined()
    expect(kp.publicKey).toBeDefined()
    expect(kp.path).toBe("m/44'/236'/0'/0/0")
  })

  it('derives change key at m/44\'/236\'/0\'/1/0', () => {
    const w = newTestWallet()
    const kp = w.deriveFeeKey(INTERNAL_CHAIN, 0)
    expect(kp.path).toBe("m/44'/236'/0'/1/0")
  })

  it('different chains produce different keys', () => {
    const w = newTestWallet()
    const kp0 = w.deriveFeeKey(EXTERNAL_CHAIN, 0)
    const kp1 = w.deriveFeeKey(INTERNAL_CHAIN, 0)
    expect(kp0.publicKey.toDER('hex')).not.toBe(kp1.publicKey.toDER('hex'))
  })

  it('is deterministic', () => {
    const w = newTestWallet()
    const kp1 = w.deriveFeeKey(EXTERNAL_CHAIN, 5)
    const kp2 = w.deriveFeeKey(EXTERNAL_CHAIN, 5)
    expect(kp1.publicKey.toDER('hex')).toBe(kp2.publicKey.toDER('hex'))
  })

  it('different indices produce different keys', () => {
    const w = newTestWallet()
    const kp0 = w.deriveFeeKey(EXTERNAL_CHAIN, 0)
    const kp1 = w.deriveFeeKey(EXTERNAL_CHAIN, 1)
    expect(kp0.publicKey.toDER('hex')).not.toBe(kp1.publicKey.toDER('hex'))
  })

  it('throws for invalid chain value (> 1)', () => {
    const w = newTestWallet()
    expect(() => w.deriveFeeKey(2, 0)).toThrow(DerivationFailedError)
    expect(() => w.deriveFeeKey(2, 0)).toThrow(/invalid chain 2/)
  })
})

// ---------------------------------------------------------------------------
// Vault root key derivation
// ---------------------------------------------------------------------------

describe('deriveVaultRootKey', () => {
  it('derives vault 0 root at m/44\'/236\'/1\'/0/0', () => {
    const w = newTestWallet()
    const kp = w.deriveVaultRootKey(0)
    expect(kp.path).toBe("m/44'/236'/1'/0/0")
  })

  it('derives vault 1 root at m/44\'/236\'/2\'/0/0', () => {
    const w = newTestWallet()
    const kp = w.deriveVaultRootKey(1)
    expect(kp.path).toBe("m/44'/236'/2'/0/0")
  })

  it('different vaults produce different keys', () => {
    const w = newTestWallet()
    const kp0 = w.deriveVaultRootKey(0)
    const kp1 = w.deriveVaultRootKey(1)
    expect(kp0.publicKey.toDER('hex')).not.toBe(kp1.publicKey.toDER('hex'))
  })
})

// ---------------------------------------------------------------------------
// Node key derivation
// ---------------------------------------------------------------------------

describe('deriveNodeKey', () => {
  it('derives root directory (no filePath)', () => {
    const w = newTestWallet()
    const kp = w.deriveNodeKey(0)
    expect(kp.path).toBe("m/44'/236'/1'/0/0")
  })

  it('derives root directory (null filePath)', () => {
    const w = newTestWallet()
    const kp = w.deriveNodeKey(0, undefined, undefined)
    expect(kp.path).toBe("m/44'/236'/1'/0/0")
  })

  it('derives root directory (empty filePath)', () => {
    const w = newTestWallet()
    const kp = w.deriveNodeKey(0, [], [])
    expect(kp.path).toBe("m/44'/236'/1'/0/0")
  })

  it('empty slices and undefined derive the same key', () => {
    const w = newTestWallet()
    const kp1 = w.deriveNodeKey(0, [], [])
    const kp2 = w.deriveNodeKey(0)
    expect(kp1.publicKey.toDER('hex')).toBe(kp2.publicKey.toDER('hex'))
  })

  it('derives child node (hardened by default)', () => {
    const w = newTestWallet()
    const kp = w.deriveNodeKey(0, [1])
    expect(kp.path).toBe("m/44'/236'/1'/0/0/1'")
  })

  it('derives nested path', () => {
    const w = newTestWallet()
    const kp = w.deriveNodeKey(0, [3, 1, 7])
    expect(kp.path).toBe("m/44'/236'/1'/0/0/3'/1'/7'")
  })

  it('derives non-hardened path when explicitly specified', () => {
    const w = newTestWallet()
    const kp = w.deriveNodeKey(0, [1, 2], [false, false])
    expect(kp.path).toBe("m/44'/236'/1'/0/0/1/2")
  })

  it('derives mixed hardened path', () => {
    const w = newTestWallet()
    const kp = w.deriveNodeKey(0, [1, 2], [false, true])
    expect(kp.path).toBe("m/44'/236'/1'/0/0/1/2'")
  })

  it('partial hardened array defaults remaining to hardened', () => {
    const w = newTestWallet()
    const kp = w.deriveNodeKey(0, [1, 2, 3], [false])
    expect(kp.path).toBe("m/44'/236'/1'/0/0/1/2'/3'")
  })

  it('default (null) hardened = all hardened (design decision #82)', () => {
    const w = newTestWallet()
    const kpDefault = w.deriveNodeKey(0, [5])
    const kpExplicit = w.deriveNodeKey(0, [5], [true])
    expect(kpDefault.publicKey.toDER('hex')).toBe(kpExplicit.publicKey.toDER('hex'))
  })

  it('is deterministic', () => {
    const w = newTestWallet()
    const kp1 = w.deriveNodeKey(0, [1, 2, 3])
    const kp2 = w.deriveNodeKey(0, [1, 2, 3])
    expect(kp1.publicKey.toDER('hex')).toBe(kp2.publicKey.toDER('hex'))
  })

  it('different vaults produce different keys for same path', () => {
    const w = newTestWallet()
    const kp0 = w.deriveNodeKey(0, [1])
    const kp1 = w.deriveNodeKey(1, [1])
    expect(kp0.publicKey.toDER('hex')).not.toBe(kp1.publicKey.toDER('hex'))
  })

  it('same seed produces same keys', () => {
    const w1 = newTestWallet()
    const w2 = newTestWallet()
    const kp1 = w1.deriveNodeKey(0, [1, 2])
    const kp2 = w2.deriveNodeKey(0, [1, 2])
    expect(kp1.publicKey.toDER('hex')).toBe(kp2.publicKey.toDER('hex'))
  })

  it('different seeds produce different keys', () => {
    const seed1 = seedFromMnemonic(TEST_MNEMONIC, '')
    const seed2 = seedFromMnemonic(TEST_MNEMONIC, 'different-passphrase')
    const w1 = new Wallet(seed1)
    const w2 = new Wallet(seed2)
    const kp1 = w1.deriveNodeKey(0, [1])
    const kp2 = w2.deriveNodeKey(0, [1])
    expect(kp1.publicKey.toDER('hex')).not.toBe(kp2.publicKey.toDER('hex'))
  })

  it('throws PathTooDeepError for depth > 64', () => {
    const w = newTestWallet()
    const deepPath = new Array(MAX_PATH_DEPTH + 1).fill(1)
    expect(() => w.deriveNodeKey(0, deepPath)).toThrow(PathTooDeepError)
  })

  it('succeeds at exactly MAX_PATH_DEPTH', () => {
    const w = newTestWallet()
    const path = new Array(MAX_PATH_DEPTH).fill(1)
    const kp = w.deriveNodeKey(0, path)
    expect(kp).toBeDefined()
    expect(kp.publicKey).toBeDefined()
  })

  it('throws FileIndexOutOfRangeError for index > MAX_FILE_INDEX', () => {
    const w = newTestWallet()
    const outOfRange = MAX_FILE_INDEX + 1
    expect(() => w.deriveNodeKey(0, [outOfRange])).toThrow(FileIndexOutOfRangeError)
  })

  it('succeeds at exactly MAX_FILE_INDEX', () => {
    const w = newTestWallet()
    const kp = w.deriveNodeKey(0, [MAX_FILE_INDEX])
    expect(kp).toBeDefined()
    expect(kp.publicKey).toBeDefined()
  })

  it('rejects multiple out-of-range indices', () => {
    const w = newTestWallet()
    const outOfRange = MAX_FILE_INDEX + 1
    expect(() => w.deriveNodeKey(0, [0, outOfRange])).toThrow(FileIndexOutOfRangeError)
  })

  it('rejects vault index near HARDENED boundary', () => {
    const w = newTestWallet()
    expect(() => w.deriveNodeKey(HARDENED - 1)).toThrow(FileIndexOutOfRangeError)
  })

  it('handles large vault index (1000)', () => {
    const w = newTestWallet()
    const kp = w.deriveNodeKey(1000)
    expect(kp.path).toContain("m/44'/236'/1001'/0/0")
    expect(kp.publicKey).toBeDefined()
  })
})

// ---------------------------------------------------------------------------
// Full workflow integration
// ---------------------------------------------------------------------------

describe('full wallet workflow', () => {
  it('runs a complete derivation workflow', () => {
    const seed = seedFromMnemonic(TEST_MNEMONIC, 'my-passphrase')
    expect(seed).toHaveLength(64)

    const w = new Wallet(seed, MainNet)

    // Vault root key
    const rootKey = w.deriveVaultRootKey(0)
    expect(rootKey.path).toContain("m/44'/236'/1'/0/0")

    // File key
    const fileKey = w.deriveNodeKey(0, [1])
    expect(fileKey.path).toContain("m/44'/236'/1'/0/0/1'")

    // Fee key
    const feeKey = w.deriveFeeKey(EXTERNAL_CHAIN, 0)
    expect(feeKey.privateKey).toBeDefined()
  })
})
