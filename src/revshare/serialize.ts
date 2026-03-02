import type { RegistryState, RevShareEntry, ShareData, ISOPoolState } from './types.js'
import {
  ErrInvalidRegistryData,
  ErrInvalidShareData,
  ErrInvalidISOPoolData,
  ErrTooManyEntries,
  RevShareError,
} from './errors.js'

// --- Constants ---

const REGISTRY_HEADER_SIZE = 44 // nodeID(32) + totalShares(8) + entryCount(4)
const REGISTRY_ENTRY_SIZE = 28 // address(20) + share(8)
const REGISTRY_TRAILER_SIZE = 1 // modeFlags(1)
const SHARE_DATA_SIZE = 40 // nodeID(32) + amount(8)
const ISO_POOL_SIZE = 68 // nodeID(32) + remaining(8) + price(8) + creator(20)
const MAX_UINT32 = 0xffffffff

// --- Registry ---

/**
 * Serialize a RegistryState to binary format.
 *
 * Layout (big-endian):
 *   Header:  nodeID(32B) + totalShares(8B) + entryCount(4B)
 *   Entries: [address(20B) + share(8B)] * entryCount
 *   Trailer: modeFlags(1B)
 */
export function serializeRegistry(state: RegistryState): Uint8Array {
  if (state.entries.length > MAX_UINT32) {
    throw new RevShareError(
      `${ErrTooManyEntries().message}: ${state.entries.length} entries`,
      ErrTooManyEntries().code,
    )
  }

  const size =
    REGISTRY_HEADER_SIZE +
    REGISTRY_ENTRY_SIZE * state.entries.length +
    REGISTRY_TRAILER_SIZE
  const buf = new Uint8Array(size)
  const view = new DataView(buf.buffer)
  let offset = 0

  // nodeID (32 bytes)
  buf.set(state.nodeID.subarray(0, 32), offset)
  offset += 32

  // totalShares (8 bytes, big-endian)
  writeBigUint64BE(view, offset, state.totalShares)
  offset += 8

  // entryCount (4 bytes, big-endian)
  view.setUint32(offset, state.entries.length)
  offset += 4

  // entries
  for (const entry of state.entries) {
    buf.set(entry.address.subarray(0, 20), offset)
    offset += 20
    writeBigUint64BE(view, offset, entry.share)
    offset += 8
  }

  // modeFlags (1 byte)
  buf[offset] = state.modeFlags & 0xff

  return buf
}

/**
 * Deserialize binary data into a RegistryState.
 */
export function deserializeRegistry(data: Uint8Array): RegistryState {
  if (data.length < REGISTRY_HEADER_SIZE + REGISTRY_TRAILER_SIZE) {
    throw new RevShareError(
      `${ErrInvalidRegistryData().message}: too short (${data.length} bytes)`,
      ErrInvalidRegistryData().code,
    )
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  let offset = 0

  // nodeID (32 bytes)
  const nodeID = new Uint8Array(32)
  nodeID.set(data.subarray(offset, offset + 32))
  offset += 32

  // totalShares (8 bytes, big-endian)
  const totalShares = readBigUint64BE(view, offset)
  offset += 8

  // entryCount (4 bytes, big-endian)
  const numEntries = view.getUint32(offset)
  offset += 4

  const expectedSize =
    REGISTRY_HEADER_SIZE +
    REGISTRY_ENTRY_SIZE * numEntries +
    REGISTRY_TRAILER_SIZE
  if (data.length < expectedSize) {
    throw new RevShareError(
      `${ErrInvalidRegistryData().message}: expected ${expectedSize} bytes for ${numEntries} entries, got ${data.length}`,
      ErrInvalidRegistryData().code,
    )
  }

  // entries
  const entries: RevShareEntry[] = new Array(numEntries)
  for (let i = 0; i < numEntries; i++) {
    const address = new Uint8Array(20)
    address.set(data.subarray(offset, offset + 20))
    offset += 20
    const share = readBigUint64BE(view, offset)
    offset += 8
    entries[i] = { address, share }
  }

  // modeFlags (1 byte)
  const modeFlags = data[offset]

  return { nodeID, totalShares, entries, modeFlags }
}

// --- ShareData ---

/**
 * Serialize a ShareData to binary format.
 *
 * Layout (40 bytes, big-endian):
 *   nodeID(32B) + amount(8B)
 */
export function serializeShare(data: ShareData): Uint8Array {
  const buf = new Uint8Array(SHARE_DATA_SIZE)
  const view = new DataView(buf.buffer)
  buf.set(data.nodeID.subarray(0, 32), 0)
  writeBigUint64BE(view, 32, data.amount)
  return buf
}

/**
 * Deserialize binary data into a ShareData.
 */
export function deserializeShare(data: Uint8Array): ShareData {
  if (!data || data.length !== SHARE_DATA_SIZE) {
    throw new RevShareError(
      `${ErrInvalidShareData().message}: expected ${SHARE_DATA_SIZE} bytes, got ${data?.length ?? 0}`,
      ErrInvalidShareData().code,
    )
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const nodeID = new Uint8Array(32)
  nodeID.set(data.subarray(0, 32))
  const amount = readBigUint64BE(view, 32)
  return { nodeID, amount }
}

// --- ISOPoolState ---

/**
 * Serialize an ISOPoolState to binary format.
 *
 * Layout (68 bytes, big-endian):
 *   nodeID(32B) + remainingShares(8B) + pricePerShare(8B) + creatorAddr(20B)
 */
export function serializeISOPool(state: ISOPoolState): Uint8Array {
  const buf = new Uint8Array(ISO_POOL_SIZE)
  const view = new DataView(buf.buffer)
  buf.set(state.nodeID.subarray(0, 32), 0)
  writeBigUint64BE(view, 32, state.remainingShares)
  writeBigUint64BE(view, 40, state.pricePerShare)
  buf.set(state.creatorAddr.subarray(0, 20), 48)
  return buf
}

/**
 * Deserialize binary data into an ISOPoolState.
 */
export function deserializeISOPool(data: Uint8Array): ISOPoolState {
  if (!data || data.length !== ISO_POOL_SIZE) {
    throw new RevShareError(
      `${ErrInvalidISOPoolData().message}: expected ${ISO_POOL_SIZE} bytes, got ${data?.length ?? 0}`,
      ErrInvalidISOPoolData().code,
    )
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const nodeID = new Uint8Array(32)
  nodeID.set(data.subarray(0, 32))
  const remainingShares = readBigUint64BE(view, 32)
  const pricePerShare = readBigUint64BE(view, 40)
  const creatorAddr = new Uint8Array(20)
  creatorAddr.set(data.subarray(48, 68))
  return { nodeID, remainingShares, pricePerShare, creatorAddr }
}

// --- Helpers ---

/** Write a BigInt as a big-endian uint64 into a DataView. */
function writeBigUint64BE(view: DataView, offset: number, value: bigint): void {
  view.setBigUint64(offset, value, false) // false = big-endian
}

/** Read a big-endian uint64 from a DataView as BigInt. */
function readBigUint64BE(view: DataView, offset: number): bigint {
  return view.getBigUint64(offset, false) // false = big-endian
}
