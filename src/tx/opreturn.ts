import type { PublicKey } from '@bsv/sdk'
import {
  NilParamError,
  InvalidPayloadError,
  InvalidParentTxIDError,
  InvalidOPReturnError,
  NotMetanetTxError,
} from './errors.js'
import { timingSafeEqual } from '../util.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Metanet protocol flag: "meta" in ASCII. */
export const META_FLAG = new Uint8Array([0x6d, 0x65, 0x74, 0x61])

/**
 * Minimum P2PKH output value in satoshis.
 * BSV has removed the dust limit; 1 sat is the protocol minimum.
 */
export const DUST_LIMIT = 1n

/** Default fee rate in sat/KB (fallback when callers pass 0). */
export const DEFAULT_FEE_RATE = 100n

/** Length of a compressed public key. */
export const COMPRESSED_PUB_KEY_LEN = 33

/** Length of a transaction ID. */
export const TXID_LEN = 32

// ---------------------------------------------------------------------------
// OP_RETURN builder / parser
// ---------------------------------------------------------------------------

/**
 * Construct the OP_RETURN data pushes for a Metanet node.
 *
 * Layout:
 * - pushdata[0]: MetaFlag    (4 bytes, "meta")
 * - pushdata[1]: P_node      (33 bytes, compressed pubkey)
 * - pushdata[2]: TxID_parent (0 bytes for root, 32 bytes otherwise)
 * - pushdata[3]: Payload     (variable length, TLV-encoded)
 *
 * @returns An array of Uint8Array push data elements.
 */
export function buildOPReturnData(
  pNode: PublicKey,
  parentTxID: Uint8Array,
  payload: Uint8Array,
): Uint8Array[] {
  if (pNode == null) {
    throw new NilParamError('P_node public key is required')
  }
  if (payload.length === 0) {
    throw new InvalidPayloadError('payload is empty')
  }
  if (parentTxID.length !== 0 && parentTxID.length !== TXID_LEN) {
    throw new InvalidParentTxIDError(parentTxID.length)
  }

  const pNodeBytes = Uint8Array.from(pNode.toDER() as number[])
  if (pNodeBytes.length !== COMPRESSED_PUB_KEY_LEN) {
    throw new NilParamError(`invalid compressed public key length: ${pNodeBytes.length}`)
  }

  return [
    META_FLAG,    // pushdata[0]: "meta"
    pNodeBytes,   // pushdata[1]: P_node
    parentTxID,   // pushdata[2]: TxID_parent (empty for root)
    payload,      // pushdata[3]: TLV payload
  ]
}

/**
 * Extract Metanet fields from OP_RETURN data pushes.
 *
 * @returns An object with pNode (compressed bytes), parentTxID, and payload.
 */
export function parseOPReturnData(pushes: Uint8Array[]): {
  pNode: Uint8Array
  parentTxID: Uint8Array
  payload: Uint8Array
} {
  if (pushes.length < 4) {
    throw new InvalidOPReturnError(
      `expected 4 data pushes, got ${pushes.length}`,
    )
  }

  // Verify MetaFlag
  if (!timingSafeEqual(pushes[0], META_FLAG)) {
    throw new NotMetanetTxError()
  }

  // P_node (33 bytes compressed pubkey)
  const pNode = pushes[1]
  if (pNode.length !== COMPRESSED_PUB_KEY_LEN) {
    throw new InvalidOPReturnError(
      `P_node must be ${COMPRESSED_PUB_KEY_LEN} bytes, got ${pNode.length}`,
    )
  }

  // TxID_parent (0 or 32 bytes)
  const parentTxID = pushes[2]
  if (parentTxID.length !== 0 && parentTxID.length !== TXID_LEN) {
    throw new InvalidOPReturnError(
      `parent TxID must be 0 or ${TXID_LEN} bytes, got ${parentTxID.length}`,
    )
  }

  // Payload
  const payload = pushes[3]
  if (payload.length === 0) {
    throw new InvalidOPReturnError('payload is empty')
  }

  return { pNode, parentTxID, payload }
}

// ---------------------------------------------------------------------------
// Fee estimation
// ---------------------------------------------------------------------------

/**
 * Estimate the transaction fee for a given size and fee rate.
 * Returns ceil(txSizeBytes * feeRate / 1000).
 */
export function estimateFee(txSizeBytes: number, feeRate: bigint): bigint {
  const rate = feeRate === 0n ? DEFAULT_FEE_RATE : feeRate
  const size = BigInt(txSizeBytes)
  const fee = size * rate
  // Ceiling division by 1000
  return (fee + 999n) / 1000n
}

/**
 * Provide a rough estimate of transaction size in bytes.
 *
 * Base: version(4) + locktime(4) + input count varint(1) + output count varint(1) = 10
 * Per input: prevhash(32) + previndex(4) + scriptlen varint(1) + script(~107 P2PKH) + sequence(4) = 148
 * Per output: value(8) + scriptlen varint(1) + script(~25 P2PKH) = 34
 * OP_RETURN output: value(8) + scriptlen varint(3) + OP_FALSE(1) + OP_RETURN(1) + pushdata = 13 + pushdata
 * pushdata: MetaFlag(5) + P_node(34) + TxID_parent(33) + payload(varies) + pushdata headers
 */
export function estimateTxSize(
  numInputs: number,
  numOutputs: number,
  payloadSize: number,
): number {
  const base = 10
  const inputs = numInputs * 148
  const outputs = numOutputs * 34
  const opReturn =
    13 + 4 + 1 + COMPRESSED_PUB_KEY_LEN + 1 + TXID_LEN + 1 + payloadSize + 4
  return base + inputs + outputs + opReturn
}
