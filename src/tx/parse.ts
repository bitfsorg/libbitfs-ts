import { META_FLAG, COMPRESSED_PUB_KEY_LEN, TXID_LEN } from './opreturn.js'
import { timingSafeEqual } from '../util.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Minimal representation of a transaction output for parsing.
 */
export interface TxOutput {
  /** Output value in satoshis. */
  value: bigint
  /** Raw locking script bytes. */
  scriptPubKey: Uint8Array
}

/**
 * Represents one parsed Metanet node operation extracted from a TX.
 */
export interface ParsedNodeOp {
  /** Compressed public key (33 bytes). */
  pNode: Uint8Array
  /** Parent transaction ID: 0 bytes for root creation, 32 bytes otherwise. */
  parentTxID: Uint8Array
  /** TLV-encoded metadata payload. */
  payload: Uint8Array
  /** Output index of the OP_RETURN. */
  vout: number
  /** Output index of the paired P2PKH dust output (0 for deletes). */
  nodeVout: number
  /** True when this op has no paired P2PKH refresh output. */
  isDelete: boolean
}

// ---------------------------------------------------------------------------
// Script opcodes
// ---------------------------------------------------------------------------

/** OP_FALSE / OP_0 */
const OP_FALSE = 0x00
/** OP_RETURN */
const OP_RETURN = 0x6a
/** OP_PUSHDATA1: next 1 byte is length */
const OP_PUSHDATA1 = 0x4c
/** OP_PUSHDATA2: next 2 bytes (LE) are length */
const OP_PUSHDATA2 = 0x4d
/** OP_PUSHDATA4: next 4 bytes (LE) are length */
const OP_PUSHDATA4 = 0x4e
/** OP_DUP */
const OP_DUP = 0x76
/** OP_HASH160 */
const OP_HASH160 = 0xa9
/** OP_EQUALVERIFY */
const OP_EQUALVERIFY = 0x88
/** OP_CHECKSIG */
const OP_CHECKSIG = 0xac

// ---------------------------------------------------------------------------
// Internal: push data parser
// ---------------------------------------------------------------------------

/**
 * Parse Bitcoin script push data items from an OP_FALSE OP_RETURN script.
 *
 * @param scriptBytes - Raw locking script bytes.
 * @returns Array of push data Uint8Arrays, or null if not a valid OP_RETURN.
 */
function parseMetanetOPReturn(scriptBytes: Uint8Array): Uint8Array[] | null {
  // Minimum: OP_FALSE(1) + OP_RETURN(1) + at least 4 push items
  if (scriptBytes.length < 6) {
    return null
  }

  // Check OP_FALSE (0x00) OP_RETURN (0x6a) prefix.
  if (scriptBytes[0] !== OP_FALSE || scriptBytes[1] !== OP_RETURN) {
    return null
  }

  // Parse push data portion after the 2-byte prefix.
  const data = scriptBytes.subarray(2)
  const pushes: Uint8Array[] = []
  let offset = 0

  while (offset < data.length) {
    const opcode = data[offset]
    offset++

    if (opcode >= 0x01 && opcode <= 0x4b) {
      // Direct push: opcode is the byte count.
      const len = opcode
      if (offset + len > data.length) return null
      pushes.push(data.subarray(offset, offset + len))
      offset += len
    } else if (opcode === OP_PUSHDATA1) {
      // Next 1 byte is the length.
      if (offset + 1 > data.length) return null
      const len = data[offset]
      offset++
      if (offset + len > data.length) return null
      pushes.push(data.subarray(offset, offset + len))
      offset += len
    } else if (opcode === OP_PUSHDATA2) {
      // Next 2 bytes (little-endian) are the length.
      if (offset + 2 > data.length) return null
      const len = data[offset] | (data[offset + 1] << 8)
      offset += 2
      if (offset + len > data.length) return null
      pushes.push(data.subarray(offset, offset + len))
      offset += len
    } else if (opcode === OP_PUSHDATA4) {
      // Next 4 bytes (little-endian) are the length.
      if (offset + 4 > data.length) return null
      const len =
        data[offset] |
        (data[offset + 1] << 8) |
        (data[offset + 2] << 16) |
        ((data[offset + 3] << 24) >>> 0)
      offset += 4
      if (offset + len > data.length) return null
      pushes.push(data.subarray(offset, offset + len))
      offset += len
    } else if (opcode === 0x00) {
      // OP_0 pushes an empty byte array.
      pushes.push(new Uint8Array(0))
    } else {
      // Non-push opcode encountered; stop parsing.
      break
    }
  }

  // Need at least 4 pushes (MetaFlag, PNode, ParentTxID, Payload).
  if (pushes.length < 4) {
    return null
  }

  // Verify MetaFlag.
  if (!timingSafeEqual(pushes[0], META_FLAG)) {
    return null
  }

  return pushes
}

/**
 * Returns true if an output is a dust (1 sat) standard P2PKH output.
 * This is the signature of a node refresh output in MutationBatch.
 */
function isDustP2PKHOutput(out: TxOutput): boolean {
  if (out.value !== 1n) {
    return false
  }

  const s = out.scriptPubKey
  if (s.length !== 25) {
    return false
  }

  return (
    s[0] === OP_DUP &&
    s[1] === OP_HASH160 &&
    s[2] === 0x14 &&
    s[23] === OP_EQUALVERIFY &&
    s[24] === OP_CHECKSIG
  )
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scan all outputs of a transaction and extract Metanet node operations.
 *
 * Each OP_FALSE OP_RETURN output containing the Metanet flag is paired with
 * the following P2PKH dust output. This supports the multi-OP_RETURN format
 * used by MutationBatch where a single TX contains multiple node operations.
 *
 * @param outputs - Array of transaction outputs.
 * @returns Array of parsed node operations (empty if none found).
 */
export function parseTxNodeOps(outputs: TxOutput[]): ParsedNodeOp[] {
  const ops: ParsedNodeOp[] = []

  for (let i = 0; i < outputs.length; i++) {
    const out = outputs[i]

    // Check if this output is an OP_RETURN with Metanet flag.
    const pushes = parseMetanetOPReturn(out.scriptPubKey)
    if (pushes == null) {
      continue
    }

    // Extract fields from the push data.
    const pNode = pushes[1]
    if (pNode.length !== COMPRESSED_PUB_KEY_LEN) {
      continue
    }

    const parentTxID = pushes[2]
    if (parentTxID.length !== 0 && parentTxID.length !== TXID_LEN) {
      continue
    }

    const payload = pushes[3]
    if (payload.length === 0) {
      continue
    }

    // If next output is dust-P2PKH, this is create/update/create-root.
    if (i + 1 < outputs.length && isDustP2PKHOutput(outputs[i + 1])) {
      ops.push({
        pNode: Uint8Array.from(pNode),
        parentTxID: Uint8Array.from(parentTxID),
        payload: Uint8Array.from(payload),
        vout: i,
        nodeVout: i + 1,
        isDelete: false,
      })

      // Skip paired P2PKH output.
      i++
      continue
    }

    // No paired dust-P2PKH means delete operation.
    ops.push({
      pNode: Uint8Array.from(pNode),
      parentTxID: Uint8Array.from(parentTxID),
      payload: Uint8Array.from(payload),
      vout: i,
      nodeVout: 0,
      isDelete: true,
    })
  }

  return ops
}
