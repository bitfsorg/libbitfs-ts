/**
 * Network configurations for BSV networks.
 *
 * Defines MainNet, TestNet, and RegTest presets matching the Go implementation.
 */

import { InvalidNetworkError } from './errors.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Network parameters for a BSV network. */
export interface NetworkConfig {
  /** Network name: 'mainnet', 'testnet', or 'regtest'. */
  name: string
  /** Version byte for P2PKH addresses. */
  addressVersion: number
  /** Version byte for P2SH addresses. */
  p2shVersion: number
  /** Default peer-to-peer port. */
  defaultPort: number
  /** Default JSON-RPC port. */
  rpcPort: number
  /** DNS seed hostnames for peer discovery. */
  dnsSeeds: string[]
  /** Genesis block hash (display/big-endian hex). */
  genesisHash: string
}

// ---------------------------------------------------------------------------
// Predefined Networks
// ---------------------------------------------------------------------------

/** BSV Mainnet configuration. */
export const MainNet: NetworkConfig = {
  name: 'mainnet',
  addressVersion: 0x00,
  p2shVersion: 0x05,
  defaultPort: 8333,
  rpcPort: 8332,
  dnsSeeds: ['seed.bitcoinsv.io', 'seed.satoshisvision.network'],
  genesisHash: '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
}

/** BSV Testnet configuration. */
export const TestNet: NetworkConfig = {
  name: 'testnet',
  addressVersion: 0x6f,
  p2shVersion: 0xc4,
  defaultPort: 18333,
  rpcPort: 18332,
  dnsSeeds: ['testnet-seed.bitcoinsv.io'],
  genesisHash: '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943',
}

/** BSV Regtest configuration. */
export const RegTest: NetworkConfig = {
  name: 'regtest',
  addressVersion: 0x6f,
  p2shVersion: 0xc4,
  defaultPort: 18444,
  rpcPort: 18443,
  dnsSeeds: [],
  genesisHash: '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

const predefined: Record<string, NetworkConfig> = {
  mainnet: MainNet,
  testnet: TestNet,
  regtest: RegTest,
}

/**
 * Get a predefined network by name.
 *
 * @param name - 'mainnet', 'testnet', or 'regtest'
 * @returns The matching NetworkConfig
 * @throws InvalidNetworkError if the name is not recognized
 */
export function getNetwork(name: string): NetworkConfig {
  const net = predefined[name]
  if (!net) {
    throw new InvalidNetworkError(name)
  }
  return net
}
