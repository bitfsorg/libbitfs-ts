import {
  OP,
  Script,
  LockingScript,
  UnlockingScript,
  Transaction,
  P2PKH,
  TransactionSignature,
  Hash,
} from '@bsv/sdk'
import type { BuyerRefundParams } from './types.js'
import {
  DEFAULT_HTLC_TIMEOUT,
  MIN_HTLC_TIMEOUT,
  MAX_HTLC_TIMEOUT,
  PUB_KEY_HASH_LEN,
  DEFAULT_HTLC_FEE_RATE,
} from './types.js'
import {
  ErrInvalidParams,
  ErrInvalidTx,
  ErrInsufficientPayment,
  ErrNoMatchingOutput,
} from './errors.js'
import { toHex, timingSafeEqual } from '../util.js'

// ---------------------------------------------------------------------------
// verifyHTLCFunding
// ---------------------------------------------------------------------------

/**
 * Verifies a funding transaction has an output whose locking script matches
 * the expected HTLC script with at least minAmount satoshis.
 * Returns the output index (vout) of the first matching HTLC output.
 *
 * @throws On empty raw transaction, nil expected script, or no matching output.
 */
export function verifyHTLCFunding(
  rawTx: Uint8Array,
  expectedScript: Uint8Array,
  minAmount: bigint,
): number {
  if (rawTx == null || rawTx.length === 0) {
    throw new Error(`${ErrInvalidTx().message}: empty raw transaction`)
  }
  if (expectedScript == null || expectedScript.length === 0) {
    throw new Error(`${ErrInvalidParams().message}: nil expected script`)
  }

  const tx = Transaction.fromBinary(Array.from(rawTx))

  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i]
    if (output.lockingScript == null) {
      continue
    }

    const scriptBytes = Uint8Array.from(output.lockingScript.toBinary())
    if (scriptBytes.length !== expectedScript.length) {
      continue
    }
    if (!timingSafeEqual(scriptBytes, expectedScript)) {
      continue
    }

    const outputAmount = BigInt(output.satoshis ?? 0)
    if (outputAmount < minAmount) {
      throw new Error(
        `${ErrInsufficientPayment().message}: output has ${outputAmount} satoshis, need ${minAmount}`,
      )
    }
    return i
  }

  throw ErrNoMatchingOutput()
}

// ---------------------------------------------------------------------------
// buildBuyerRefundTx (on-chain, buyer-only)
// ---------------------------------------------------------------------------

/**
 * Builds an on-chain refund transaction that the buyer can broadcast
 * unilaterally after the timeout -- no seller cooperation is needed.
 *
 * The transaction sets nLockTime = params.timeout and sequence = 0xfffffffe to
 * enable nLockTime enforcement. The unlocking script format matches the sCrypt
 * refund() ABI (index 1):
 *
 *   <sig> <pubkey> <sighash_preimage> OP_1
 *
 * Where OP_1 selects the refund method (index 1), and the sighash preimage is
 * the BIP143 preimage that the contract verifies via OP_PUSH_TX.
 *
 * @returns Serialized signed refund transaction bytes.
 */
export function buildBuyerRefundTx(params: BuyerRefundParams): Uint8Array {
  if (params == null) {
    throw new Error(`${ErrInvalidParams().message}: nil params`)
  }
  if (params.buyerPrivKey == null) {
    throw new Error(`${ErrInvalidParams().message}: nil buyer private key`)
  }
  if (params.fundingTxID.length !== 32) {
    throw new Error(`${ErrInvalidParams().message}: funding txid must be 32 bytes`)
  }
  if (params.htlcScript == null || params.htlcScript.length === 0) {
    throw new Error(`${ErrInvalidParams().message}: empty HTLC script`)
  }
  if (params.outputAddr.length !== PUB_KEY_HASH_LEN) {
    throw new Error(
      `${ErrInvalidParams().message}: output address must be ${PUB_KEY_HASH_LEN} bytes`,
    )
  }
  if (params.fundingAmount <= 0n) {
    throw new Error(`${ErrInvalidParams().message}: funding amount must be greater than zero`)
  }

  let timeout = params.timeout
  if (timeout === 0) {
    timeout = DEFAULT_HTLC_TIMEOUT
  }
  if (timeout < MIN_HTLC_TIMEOUT) {
    throw new Error(
      `${ErrInvalidParams().message}: timeout ${timeout} below minimum ${MIN_HTLC_TIMEOUT} blocks`,
    )
  }
  if (timeout > MAX_HTLC_TIMEOUT) {
    throw new Error(
      `${ErrInvalidParams().message}: timeout ${timeout} exceeds maximum ${MAX_HTLC_TIMEOUT} blocks`,
    )
  }

  const feeRate = (params.feeRate != null && params.feeRate > 0) ? params.feeRate : DEFAULT_HTLC_FEE_RATE

  // Estimate refund tx size: ~10 overhead + ~(73 + 33 + preimage ~200 + 1)
  // unlocking + script + ~40 output. The BIP143 sighash preimage is typically
  // ~180 bytes; we use 200 as conservative estimate.
  const estSize = 10 + 73 + 33 + 200 + 1 + params.htlcScript.length + 40
  const estFee = BigInt(estSize) * BigInt(feeRate)

  if (params.fundingAmount <= estFee) {
    throw new Error(
      `${ErrInsufficientPayment().message}: funding amount ${params.fundingAmount} too small for fee ${estFee}`,
    )
  }

  const outputAmount = params.fundingAmount - estFee
  const fundingTxIDHex = toHex(params.fundingTxID)

  const tx = new Transaction()
  tx.lockTime = timeout

  // Sequence must be < 0xffffffff for nLockTime to be enforced by miners.
  tx.addInput({
    sourceTXID: fundingTxIDHex,
    sourceOutputIndex: params.fundingVout,
    sequence: 0xfffffffe,
  })

  // Set source transaction for sighash computation.
  const sourceTx = new Transaction()
  for (let v = 0; v < params.fundingVout; v++) {
    sourceTx.addOutput({
      lockingScript: LockingScript.fromBinary([]),
      satoshis: 0,
    })
  }
  sourceTx.addOutput({
    lockingScript: LockingScript.fromBinary(Array.from(params.htlcScript)),
    satoshis: Number(params.fundingAmount),
  })
  tx.inputs[0].sourceTransaction = sourceTx
  tx.inputs[0].sourceOutputIndex = params.fundingVout

  // Output: P2PKH to buyer.
  const p2pkh = new P2PKH()
  const outputScript = p2pkh.lock(Array.from(params.outputAddr))
  tx.addOutput({
    lockingScript: outputScript,
    satoshis: Number(outputAmount),
  })

  // Compute BIP143 sighash preimage (used by sCrypt's OP_PUSH_TX).
  const scope = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID

  const preimage = TransactionSignature.format({
    sourceTXID: fundingTxIDHex,
    sourceOutputIndex: params.fundingVout,
    sourceSatoshis: Number(params.fundingAmount),
    transactionVersion: tx.version,
    otherInputs: [],
    outputs: tx.outputs,
    inputIndex: 0,
    subscript: Script.fromBinary(Array.from(params.htlcScript)),
    inputSequence: 0xfffffffe,
    lockTime: tx.lockTime,
    scope,
  })

  // Compute sighash and sign with buyer's key.
  const sigHash = Hash.hash256(preimage)
  const sig = params.buyerPrivKey.sign(sigHash)

  const derBytes = sig.toDER() as number[]
  const buyerSigBytes: number[] = [...derBytes, scope & 0xff]
  const buyerPubKey = params.buyerPrivKey.toPublicKey().toDER() as number[]

  // Build unlocking script for sCrypt refund() method (index 1):
  //   <sig> <pubkey> <sighash_preimage> OP_1
  const unlockScript = new Script()
  unlockScript.writeBin(buyerSigBytes)
  unlockScript.writeBin(buyerPubKey)
  unlockScript.writeBin(Array.from(preimage))
  unlockScript.writeOpCode(OP.OP_1)

  tx.inputs[0].unlockingScript = UnlockingScript.fromBinary(unlockScript.toBinary())

  return Uint8Array.from(tx.toBinary())
}
