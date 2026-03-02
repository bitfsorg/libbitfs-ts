/**
 * RevShareEntry represents a shareholder's record in the registry.
 * address: 20-byte P2PKH address hash
 * share: number of shares held (uint64 as bigint)
 */
export interface RevShareEntry {
  address: Uint8Array // 20 bytes
  share: bigint
}

/**
 * RegistryState represents the current state of a revenue share registry.
 * nodeID: SHA256(P_node || TxID) of the Metanet node (32 bytes)
 * totalShares: total shares issued
 * entries: current shareholders
 * modeFlags: bit 0 = ISO active, bit 1 = locked
 */
export interface RegistryState {
  nodeID: Uint8Array // 32 bytes
  totalShares: bigint
  entries: RevShareEntry[]
  modeFlags: number // uint8
}

/**
 * ShareData represents the data embedded in a Share UTXO.
 * nodeID: bound Metanet node (32 bytes)
 * amount: number of shares (uint64 as bigint)
 */
export interface ShareData {
  nodeID: Uint8Array // 32 bytes
  amount: bigint
}

/**
 * ISOPoolState represents the state of an ISO pool UTXO.
 * nodeID: bound Metanet node (32 bytes)
 * remainingShares: unsold shares
 * pricePerShare: price in satoshis
 * creatorAddr: creator's P2PKH address (20 bytes)
 */
export interface ISOPoolState {
  nodeID: Uint8Array // 32 bytes
  remainingShares: bigint
  pricePerShare: bigint
  creatorAddr: Uint8Array // 20 bytes
}

/**
 * Distribution represents a single payout in revenue distribution.
 */
export interface Distribution {
  address: Uint8Array // 20 bytes
  amount: bigint
}

/** Check if ISO pool is active (bit 0). */
export function isISOActive(state: RegistryState): boolean {
  return (state.modeFlags & 0x01) !== 0
}

/** Check if share transfers are locked (bit 1). */
export function isLocked(state: RegistryState): boolean {
  return (state.modeFlags & 0x02) !== 0
}

/** Find an entry by address. Returns [index, entry] or [-1, undefined]. */
export function findEntry(
  state: RegistryState,
  addr: Uint8Array,
): [number, RevShareEntry | undefined] {
  for (let i = 0; i < state.entries.length; i++) {
    if (bytesEqual(state.entries[i].address, addr)) {
      return [i, state.entries[i]]
    }
  }
  return [-1, undefined]
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}
