import { Transaction, UnlockingScript } from '@bsv/sdk'
import type { PublicKey, PrivateKey } from '@bsv/sdk'
import type {
  UTXO,
  BatchNodeOp,
  BatchResult,
  BatchNodeResult,
} from './types.js'
import { BatchOpType } from './types.js'
import {
  NilParamError,
  InvalidPayloadError,
  InvalidParentTxIDError,
  InsufficientFundsError,
  InvalidParamsError,
} from './errors.js'
import {
  buildOPReturnData,
  estimateFee,
  estimateTxSize,
  DEFAULT_FEE_RATE,
  DUST_LIMIT,
  TXID_LEN,
} from './opreturn.js'
import {
  buildP2PKHLockingScript,
  buildP2PKHFromHash,
  buildOPReturnScript,
  signBatchResult,
} from './sign.js'
import { toHex } from '../util.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Create a unique key for a UTXO based on its txID and vout. */
function utxoKey(utxo: UTXO): string {
  return toHex(utxo.txID) + ':' + utxo.vout
}

// ---------------------------------------------------------------------------
// MutationBatch
// ---------------------------------------------------------------------------

/**
 * MutationBatch collects multiple node operations into a single TX.
 *
 * Output layout per op:
 * - Create/Update: [OP_RETURN(MetaFlag|PNode|ParentTxID|Payload)] + [P2PKH(PNode, 1 sat)]
 * - Delete: [OP_RETURN(MetaFlag|PNode|ParentTxID|Payload)] (no dust output)
 * - CreateRoot: [OP_RETURN(MetaFlag|PNode|empty|Payload)] + [P2PKH(PNode, 1 sat)]
 * - Final output: change P2PKH
 */
export class MutationBatch {
  private ops: BatchNodeOp[] = []
  private feeInputs: UTXO[] = []
  private changeAddr: Uint8Array | null = null
  private feeRate: bigint = DEFAULT_FEE_RATE

  /** Append one node operation to the batch. */
  addNodeOp(op: BatchNodeOp): void {
    this.ops.push(op)
  }

  /** Add a UTXO to be used as fee input. */
  addFeeInput(utxo: UTXO): void {
    this.feeInputs.push(utxo)
  }

  /** Set the 20-byte P2PKH hash for the change output. */
  setChange(addr: Uint8Array): void {
    this.changeAddr = addr
  }

  /** Set the fee rate in sat/KB. */
  setFeeRate(rate: bigint): void {
    this.feeRate = rate
  }

  /** Return the number of operations in the batch. */
  opCount(): number {
    return this.ops.length
  }

  // -----------------------------------------------------------------------
  // Convenience builders
  // -----------------------------------------------------------------------

  /**
   * Add an OpCreate op for a new child node.
   * The parentUTXO is the parent's P_node UTXO to spend (Metanet edge).
   */
  addCreateChild(
    childPub: PublicKey,
    parentTxID: Uint8Array,
    payload: Uint8Array,
    parentUTXO: UTXO,
    parentPriv: PrivateKey,
  ): void {
    this.addNodeOp({
      type: BatchOpType.Create,
      pubKey: childPub,
      parentTxID,
      payload,
      inputUTXO: parentUTXO,
      privateKey: parentPriv,
    })
  }

  /** Add an OpUpdate op for updating an existing node. */
  addSelfUpdate(
    nodePub: PublicKey,
    parentTxID: Uint8Array,
    payload: Uint8Array,
    nodeUTXO: UTXO,
    nodePriv: PrivateKey,
  ): void {
    this.addNodeOp({
      type: BatchOpType.Update,
      pubKey: nodePub,
      parentTxID,
      payload,
      inputUTXO: nodeUTXO,
      privateKey: nodePriv,
    })
  }

  /** Add an OpDelete op. The node's UTXO is spent but no refresh is produced. */
  addDelete(
    nodePub: PublicKey,
    parentTxID: Uint8Array,
    payload: Uint8Array,
    nodeUTXO: UTXO,
    nodePriv: PrivateKey,
  ): void {
    this.addNodeOp({
      type: BatchOpType.Delete,
      pubKey: nodePub,
      parentTxID,
      payload,
      inputUTXO: nodeUTXO,
      privateKey: nodePriv,
    })
  }

  /** Add an OpCreateRoot op. No input UTXO needed. */
  addCreateRoot(rootPub: PublicKey, payload: Uint8Array): void {
    this.addNodeOp({
      type: BatchOpType.CreateRoot,
      pubKey: rootPub,
      parentTxID: new Uint8Array(0),
      payload,
    })
  }

  // -----------------------------------------------------------------------
  // Build
  // -----------------------------------------------------------------------

  /**
   * Construct the unsigned transaction.
   *
   * Output layout:
   *   For each op:
   *     [i]   OP_RETURN [MetaFlag, P_node, ParentTxID, Payload]
   *     [i+1] P2PKH -> P_node (1 sat)  (skipped for Delete)
   *   [last] P2PKH -> Change
   *
   * Inputs:
   *   One input per op that has InputUTXO (spending existing P_node UTXO)
   *   Fee inputs at the end
   */
  async build(): Promise<BatchResult> {
    if (this.ops.length === 0) {
      throw new InvalidPayloadError('no operations in batch')
    }
    if (this.feeInputs.length === 0) {
      throw new NilParamError('no fee inputs')
    }

    // Validate all ops.
    for (let i = 0; i < this.ops.length; i++) {
      const op = this.ops[i]
      if (op.pubKey == null) {
        throw new NilParamError(`op[${i}] PubKey is required`)
      }
      if (op.payload.length === 0) {
        throw new InvalidPayloadError(`op[${i}] has empty payload`)
      }
      if (op.parentTxID.length !== 0 && op.parentTxID.length !== TXID_LEN) {
        throw new InvalidParentTxIDError(op.parentTxID.length)
      }
      // OpCreateRoot: no InputUTXO or PrivateKey needed.
      // All other types with InputUTXO must have PrivateKey.
      if (
        op.type !== BatchOpType.CreateRoot &&
        op.inputUTXO != null &&
        op.privateKey == null
      ) {
        throw new NilParamError(`op[${i}] has inputUTXO but no privateKey`)
      }
    }

    // Validate fee inputs.
    for (let i = 0; i < this.feeInputs.length; i++) {
      if (this.feeInputs[i] == null) {
        throw new NilParamError(`feeInput[${i}] is null`)
      }
    }

    const feeRate = this.feeRate === 0n ? DEFAULT_FEE_RATE : this.feeRate

    // Dedup: track unique (TxID, Vout) pairs for node inputs.
    const seenInputs = new Set<string>()
    let numNodeInputs = 0
    for (const op of this.ops) {
      if (op.inputUTXO == null) continue
      const key = utxoKey(op.inputUTXO)
      if (!seenInputs.has(key)) {
        seenInputs.add(key)
        numNodeInputs++
      }
    }

    // Count fee inputs that don't overlap with node inputs.
    let numFeeOnly = 0
    for (const fi of this.feeInputs) {
      const key = utxoKey(fi)
      if (!seenInputs.has(key)) {
        numFeeOnly++
      }
    }

    const numInputs = numNodeInputs + numFeeOnly

    // Count outputs: 2 per non-delete op (OP_RETURN + P2PKH), 1 per delete op, + 1 change.
    let numDeleteOps = 0
    for (const op of this.ops) {
      if (op.type === BatchOpType.Delete) numDeleteOps++
    }
    const numOutputs =
      (this.ops.length - numDeleteOps) * 2 + numDeleteOps + 1

    // Total payload size for fee estimation.
    let totalPayloadSize = 0
    for (const op of this.ops) {
      totalPayloadSize += op.payload.length
    }

    // Estimate fee.
    const baseEstimate = estimateTxSize(numInputs, numOutputs, totalPayloadSize)
    const estFee = estimateFee(baseEstimate, feeRate)

    // Calculate total available funds (deduped node inputs + deduped fee inputs).
    let totalAvailable = 0n
    const seenFunds = new Set<string>()
    for (const op of this.ops) {
      if (op.inputUTXO == null) continue
      const key = utxoKey(op.inputUTXO)
      if (!seenFunds.has(key)) {
        seenFunds.add(key)
        totalAvailable += op.inputUTXO.amount
      }
    }
    for (const fi of this.feeInputs) {
      const key = utxoKey(fi)
      if (seenFunds.has(key)) continue // Fee input overlaps with a node input; skip.
      seenFunds.add(key)
      totalAvailable += fi.amount
    }

    // Total needed: DUST_LIMIT per non-delete op + fee.
    const totalDust = BigInt(this.ops.length - numDeleteOps) * DUST_LIMIT
    const totalNeeded = totalDust + estFee

    if (totalAvailable < totalNeeded) {
      throw new InsufficientFundsError(totalNeeded, totalAvailable)
    }

    // Build the @bsv/sdk Transaction.
    const sdkTx = new Transaction()

    // --- Add inputs ---

    // First: deduped node UTXO inputs (ops with existing UTXOs).
    const addedInputs = new Set<string>()
    for (const op of this.ops) {
      if (op.inputUTXO == null) continue
      const key = utxoKey(op.inputUTXO)
      if (addedInputs.has(key)) continue
      addedInputs.add(key)
      sdkTx.addInput({
        sourceTXID: toHex(op.inputUTXO.txID),
        sourceOutputIndex: op.inputUTXO.vout,
        sequence: 0xffffffff,
        unlockingScript: UnlockingScript.fromBinary([]),
      })
    }

    // Then: fee inputs (deduped against node inputs to prevent double-spend).
    for (const fi of this.feeInputs) {
      const key = utxoKey(fi)
      if (addedInputs.has(key)) continue
      addedInputs.add(key)
      sdkTx.addInput({
        sourceTXID: toHex(fi.txID),
        sourceOutputIndex: fi.vout,
        sequence: 0xffffffff,
        unlockingScript: UnlockingScript.fromBinary([]),
      })
    }

    // --- Add outputs ---

    const nodeResults: BatchNodeResult[] = new Array(this.ops.length)
    let vout = 0

    for (let i = 0; i < this.ops.length; i++) {
      const op = this.ops[i]

      // OP_RETURN output.
      const opReturnPushes = buildOPReturnData(op.pubKey, op.parentTxID, op.payload)
      const opReturnLock = buildOPReturnScript(opReturnPushes)

      sdkTx.addOutput({
        satoshis: 0,
        lockingScript: opReturnLock,
      })

      nodeResults[i] = {
        opReturnVout: vout,
        nodeVout: 0,
        nodeUTXO: undefined,
      }
      vout++

      // OpDelete: no P2PKH output -- node UTXO dies.
      if (op.type === BatchOpType.Delete) {
        continue
      }

      // P2PKH dust output for this node.
      const nodeLockScript = buildP2PKHLockingScript(op.pubKey)

      sdkTx.addOutput({
        satoshis: Number(DUST_LIMIT),
        lockingScript: nodeLockScript,
      })

      nodeResults[i].nodeVout = vout
      nodeResults[i].nodeUTXO = {
        txID: new Uint8Array(32), // Will be filled after signing
        vout,
        amount: DUST_LIMIT,
        scriptPubKey: Uint8Array.from(nodeLockScript.toBinary()),
      }
      vout++
    }

    // Change output.
    const changeAmount = totalAvailable - totalDust - estFee
    let changeUTXO: UTXO | undefined

    if (changeAmount > DUST_LIMIT) {
      if (this.changeAddr == null || this.changeAddr.length !== 20) {
        throw new InvalidParamsError('change address required (20-byte P2PKH hash)')
      }
      const changeLockScript = buildP2PKHFromHash(this.changeAddr)

      sdkTx.addOutput({
        satoshis: Number(changeAmount),
        lockingScript: changeLockScript,
      })

      changeUTXO = {
        txID: new Uint8Array(32), // Will be filled after signing
        vout,
        amount: changeAmount,
        scriptPubKey: Uint8Array.from(changeLockScript.toBinary()),
      }
    }

    // Serialize the unsigned transaction.
    const rawTx = Uint8Array.from(sdkTx.toBinary())

    return {
      rawTx,
      txID: new Uint8Array(32), // Will be filled after signing
      nodeOps: nodeResults,
      changeUTXO,
    }
  }

  // -----------------------------------------------------------------------
  // Sign
  // -----------------------------------------------------------------------

  /**
   * Sign the built BatchResult using the private keys from the batch's ops
   * and fee inputs.
   *
   * @returns The signed transaction hex string.
   */
  async sign(result: BatchResult): Promise<string> {
    return signBatchResult(result, this.ops, this.feeInputs)
  }
}
