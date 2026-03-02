import { P2PKH, OP, Script, LockingScript, Transaction } from '@bsv/sdk'
import type { PublicKey, PrivateKey } from '@bsv/sdk'
import type { UTXO } from './types.js'
import { NilParamError, ScriptBuildError, SigningFailedError } from './errors.js'
import type { BatchResult } from './types.js'
import type { BatchNodeOp } from './types.js'
import { toHex } from '../util.js'

// ---------------------------------------------------------------------------
// P2PKH script builders
// ---------------------------------------------------------------------------

/**
 * Create a P2PKH locking script for the given public key.
 * Returns LockingScript suitable for TransactionOutput.
 */
export function buildP2PKHLockingScript(pubKey: PublicKey): LockingScript {
  if (pubKey == null) {
    throw new NilParamError('public key is required')
  }
  const pubKeyHash = pubKey.toHash() as number[]
  const p2pkh = new P2PKH()
  return p2pkh.lock(pubKeyHash)
}

/**
 * Create a P2PKH locking script from a 20-byte public key hash.
 * Returns LockingScript suitable for TransactionOutput.
 */
export function buildP2PKHFromHash(pubKeyHash: Uint8Array): LockingScript {
  if (pubKeyHash.length !== 20) {
    throw new ScriptBuildError(`pubKeyHash must be 20 bytes, got ${pubKeyHash.length}`)
  }
  const p2pkh = new P2PKH()
  return p2pkh.lock(Array.from(pubKeyHash))
}

/**
 * Build an OP_FALSE OP_RETURN script from data pushes.
 */
export function buildOPReturnScript(pushes: Uint8Array[]): LockingScript {
  const script = new Script()
  // OP_FALSE OP_RETURN prefix
  script.writeOpCode(OP.OP_FALSE)
  script.writeOpCode(OP.OP_RETURN)
  // Append each data push
  for (const push of pushes) {
    script.writeBin(Array.from(push))
  }
  // Convert Script to LockingScript by creating a new LockingScript from the binary
  return LockingScript.fromBinary(script.toBinary())
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/**
 * Sign a built BatchResult using the provided ops and fee inputs.
 *
 * Reconstructs the signing UTXO array in the same order as Build() added inputs:
 * deduped node inputs first, then fee inputs.
 *
 * @returns The signed transaction hex string.
 */
export async function signBatchResult(
  result: BatchResult,
  ops: BatchNodeOp[],
  feeInputs: UTXO[],
): Promise<string> {
  if (result == null || result.rawTx.length === 0) {
    throw new SigningFailedError('BatchResult is null or has empty rawTx')
  }

  // Reconstruct signing UTXOs in input order (matching build).
  const signingUTXOs: UTXO[] = []
  const seen = new Set<string>()

  // 1. Deduped node inputs (same order as build).
  for (const op of ops) {
    if (op.inputUTXO == null) continue
    const key = utxoKey(op.inputUTXO)
    if (seen.has(key)) continue
    seen.add(key)
    signingUTXOs.push(op.inputUTXO)
  }

  // 2. Fee inputs (deduped against node inputs, matching build).
  for (const fi of feeInputs) {
    const key = utxoKey(fi)
    if (seen.has(key)) continue
    seen.add(key)
    signingUTXOs.push(fi)
  }

  // Parse the raw unsigned tx bytes.
  const sdkTx = Transaction.fromBinary(Array.from(result.rawTx))

  if (signingUTXOs.length !== sdkTx.inputs.length) {
    throw new SigningFailedError(
      `have ${signingUTXOs.length} UTXOs but tx has ${sdkTx.inputs.length} inputs`,
    )
  }

  // For each input, attach source output info and P2PKH unlocker.
  const p2pkh = new P2PKH()
  for (let i = 0; i < signingUTXOs.length; i++) {
    const utxo = signingUTXOs[i]
    if (utxo.privateKey == null) {
      throw new SigningFailedError(`utxo[${i}] has no privateKey`)
    }
    if (utxo.scriptPubKey.length === 0) {
      throw new SigningFailedError(`utxo[${i}] has empty scriptPubKey`)
    }

    const lockingScript = LockingScript.fromBinary(Array.from(utxo.scriptPubKey))

    // Set the source transaction output for sighash computation.
    sdkTx.inputs[i].sourceTransaction = undefined
    sdkTx.inputs[i].sourceTXID = toHex(utxo.txID)

    // Create a source transaction to feed the input.
    // We need to provide the output directly via a helper transaction.
    const sourceTx = new Transaction()
    // Pad outputs up to the correct vout
    for (let v = 0; v < utxo.vout; v++) {
      sourceTx.addOutput({
        lockingScript: LockingScript.fromBinary([]),
        satoshis: 0,
      })
    }
    sourceTx.addOutput({
      lockingScript,
      satoshis: Number(utxo.amount),
    })
    sdkTx.inputs[i].sourceTransaction = sourceTx
    sdkTx.inputs[i].sourceOutputIndex = utxo.vout

    // Attach the unlocking script template.
    const unlocker = p2pkh.unlock(utxo.privateKey)
    sdkTx.inputs[i].unlockingScriptTemplate = unlocker
  }

  // Sign all inputs.
  await sdkTx.sign()

  // Get signed bytes and txid.
  const signedBytes = Uint8Array.from(sdkTx.toBinary())
  const txID = Uint8Array.from(sdkTx.id() as number[])

  // Update result with signed data.
  result.rawTx = signedBytes
  result.txID = txID

  // Propagate TxID to all NodeUTXOs.
  for (const nodeOp of result.nodeOps) {
    if (nodeOp.nodeUTXO != null) {
      nodeOp.nodeUTXO.txID = txID
    }
  }
  if (result.changeUTXO != null) {
    result.changeUTXO.txID = txID
  }

  return sdkTx.toHex()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Create a unique key for a UTXO based on its txID and vout. */
function utxoKey(utxo: UTXO): string {
  return toHex(utxo.txID) + ':' + utxo.vout
}

