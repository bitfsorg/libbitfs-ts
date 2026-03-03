import { OP, Script } from '@bsv/sdk'
import {
  INVOICE_ID_LEN,
  CAPSULE_HASH_LEN,
  PUB_KEY_HASH_LEN,
} from './types.js'

// ---------------------------------------------------------------------------
// Byte offsets for extraction (plain Bitcoin Script HTLC)
// All offsets are fixed (no variable-length fields).
// ---------------------------------------------------------------------------

export const HTLC_INVOICE_ID_OFFSET = 1      // invoiceId: 16 bytes (after 0x10 push)
export const HTLC_CAPSULE_HASH_OFFSET = 21   // capsuleHash: 32 bytes (after byte[20]=0x20 push)
export const HTLC_SELLER_PKH_OFFSET = 57     // sellerPkh: 20 bytes (after byte[56]=0x14 push)
export const HTLC_BUYER_PKH_OFFSET = 83      // buyerPkh: 20 bytes (after byte[82]=0x14 push)

/** Exact script length: 106 bytes (fixed, no variable-length timeout). */
export const HTLC_MIN_SCRIPT_LEN = 106

/**
 * Builds a plain Bitcoin Script HTLC locking script.
 * Byte-identical to the Go implementation in libbitfs-go.
 *
 * Layout:
 *   <invoiceId> OP_DROP
 *   OP_IF
 *     OP_SHA256 <capsuleHash> OP_EQUALVERIFY
 *     OP_DUP OP_HASH160 <sellerPkh> OP_EQUALVERIFY OP_CHECKSIG
 *   OP_ELSE
 *     OP_DUP OP_HASH160 <buyerPkh> OP_EQUALVERIFY OP_CHECKSIG
 *   OP_ENDIF
 *
 * The timeout is NOT embedded in the script. BSV post-Genesis treats OP_CLTV
 * (0xb1) as OP_NOP2, which is rejected by standard mempool policy. Instead,
 * the timeout is enforced at the transaction level via nLockTime on the refund
 * transaction (consensus-enforced by miners).
 */
export function buildHTLCScript(
  invoiceId: Uint8Array,    // 16 bytes
  capsuleHash: Uint8Array,  // 32 bytes
  sellerPkh: Uint8Array,    // 20 bytes
  buyerPkh: Uint8Array,     // 20 bytes
): Uint8Array {
  if (invoiceId.length !== INVOICE_ID_LEN) {
    throw new Error(`invoiceId must be ${INVOICE_ID_LEN} bytes, got ${invoiceId.length}`)
  }
  if (capsuleHash.length !== CAPSULE_HASH_LEN) {
    throw new Error(`capsuleHash must be ${CAPSULE_HASH_LEN} bytes, got ${capsuleHash.length}`)
  }
  if (sellerPkh.length !== PUB_KEY_HASH_LEN) {
    throw new Error(`sellerPkh must be ${PUB_KEY_HASH_LEN} bytes, got ${sellerPkh.length}`)
  }
  if (buyerPkh.length !== PUB_KEY_HASH_LEN) {
    throw new Error(`buyerPkh must be ${PUB_KEY_HASH_LEN} bytes, got ${buyerPkh.length}`)
  }

  const s = new Script()
  s.writeBin(Array.from(invoiceId))                          // push invoiceId
  s.writeOpCode(OP.OP_DROP)
  s.writeOpCode(OP.OP_IF)
  s.writeOpCode(OP.OP_SHA256)
  s.writeBin(Array.from(capsuleHash))                        // push capsuleHash
  s.writeOpCode(OP.OP_EQUALVERIFY)
  s.writeOpCode(OP.OP_DUP)
  s.writeOpCode(OP.OP_HASH160)
  s.writeBin(Array.from(sellerPkh))                          // push sellerPkh
  s.writeOpCode(OP.OP_EQUALVERIFY)
  s.writeOpCode(OP.OP_CHECKSIG)
  s.writeOpCode(OP.OP_ELSE)
  s.writeOpCode(OP.OP_DUP)
  s.writeOpCode(OP.OP_HASH160)
  s.writeBin(Array.from(buyerPkh))                           // push buyerPkh
  s.writeOpCode(OP.OP_EQUALVERIFY)
  s.writeOpCode(OP.OP_CHECKSIG)
  s.writeOpCode(OP.OP_ENDIF)

  return Uint8Array.from(s.toBinary())
}

/** Returns true if the script matches the plain Bitcoin Script HTLC structure. */
export function isHTLCScript(scriptBytes: Uint8Array): boolean {
  if (scriptBytes.length < HTLC_MIN_SCRIPT_LEN) {
    return false
  }
  return scriptBytes[0] === 0x10 &&     // PUSH 16 bytes
         scriptBytes[17] === 0x75 &&    // OP_DROP
         scriptBytes[18] === 0x63 &&    // OP_IF
         scriptBytes[19] === 0xa8 &&    // OP_SHA256
         scriptBytes[20] === 0x20       // PUSH 32 bytes
}

// ---------------------------------------------------------------------------
// Backward compatibility exports (keep names other modules import)
// ---------------------------------------------------------------------------

/** @deprecated Use buildHTLCScript instead */
export const instantiateHTLC = buildHTLCScript

/** @deprecated Use isHTLCScript instead */
export const isArtifactScript = isHTLCScript
