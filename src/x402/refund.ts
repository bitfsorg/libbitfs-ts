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
import type {
  SellerPreSignParams,
  SellerPreSignResult,
  BuyerRefundParams,
} from './types.js'
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
  ErrFundingMismatch,
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
// buildSellerPreSignedRefund
// ---------------------------------------------------------------------------

/**
 * Builds a refund transaction and signs it with the seller's key (first
 * signature of the 2-of-2 multisig). The buyer will add their signature to
 * complete the refund. The tx uses nLockTime = timeout so it cannot be
 * broadcast until after the timeout.
 */
export async function buildSellerPreSignedRefund(
  params: SellerPreSignParams,
): Promise<SellerPreSignResult> {
  if (params == null) {
    throw new Error(`${ErrInvalidParams().message}: nil params`)
  }
  if (params.sellerPrivKey == null) {
    throw new Error(`${ErrInvalidParams().message}: nil seller private key`)
  }
  if (params.fundingTxID.length !== 32) {
    throw new Error(`${ErrInvalidParams().message}: funding txid must be 32 bytes`)
  }
  if (params.htlcScript.length === 0) {
    throw new Error(`${ErrInvalidParams().message}: empty HTLC script`)
  }
  if (params.buyerOutputAddr.length !== PUB_KEY_HASH_LEN) {
    throw new Error(
      `${ErrInvalidParams().message}: buyer output address must be ${PUB_KEY_HASH_LEN} bytes`,
    )
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

  const feeRate = params.feeRate > 0 ? params.feeRate : DEFAULT_HTLC_FEE_RATE

  // Estimate refund tx size: ~10 overhead + ~(1 + 73 + 73 + 1) unlocking
  // (OP_0 + two sigs + OP_FALSE) + script + ~40 output.
  const estSize = 10 + 1 + 73 + 73 + 1 + params.htlcScript.length + 40
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

  // Sequence must be < 0xffffffff for nLockTime to be enforced.
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
  const outputScript = p2pkh.lock(Array.from(params.buyerOutputAddr))
  tx.addOutput({
    lockingScript: outputScript,
    satoshis: Number(outputAmount),
  })

  // Compute sighash and sign with seller's key.
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

  const sigHash = Hash.hash256(preimage)
  const sig = params.sellerPrivKey.sign(sigHash)

  const sellerSigBytes = Uint8Array.from([...sig.toDER(), scope & 0xff])

  // Set a placeholder empty unlocking script so the tx can be serialized.
  // The buyer will replace this with the full multisig unlocking script.
  tx.inputs[0].unlockingScript = UnlockingScript.fromBinary([])

  return {
    txBytes: Uint8Array.from(tx.toBinary()),
    sellerSig: sellerSigBytes,
  }
}

// ---------------------------------------------------------------------------
// buildBuyerRefundTx
// ---------------------------------------------------------------------------

/**
 * Takes the seller's pre-signed refund transaction and adds the buyer's
 * signature to complete the 2-of-2 multisig. Returns a fully signed refund
 * transaction ready to broadcast (after nLockTime has passed).
 *
 * Unlocking script: OP_0 <buyer_sig+flag> <seller_sig+flag> OP_FALSE
 */
export async function buildBuyerRefundTx(
  params: BuyerRefundParams,
): Promise<Uint8Array> {
  if (params == null) {
    throw new Error(`${ErrInvalidParams().message}: nil params`)
  }
  if (params.buyerPrivKey == null) {
    throw new Error(`${ErrInvalidParams().message}: nil buyer private key`)
  }
  if (params.sellerPreSignedTx == null || params.sellerPreSignedTx.length === 0) {
    throw new Error(`${ErrInvalidParams().message}: empty seller pre-signed tx`)
  }
  if (params.sellerSig == null || params.sellerSig.length === 0) {
    throw new Error(`${ErrInvalidParams().message}: empty seller signature`)
  }
  if (params.htlcScript == null || params.htlcScript.length === 0) {
    throw new Error(`${ErrInvalidParams().message}: empty HTLC script`)
  }

  // Deserialize the pre-signed transaction to extract structure.
  let parsed: Transaction
  try {
    parsed = Transaction.fromBinary(Array.from(params.sellerPreSignedTx))
  } catch (e) {
    throw new Error(`${ErrInvalidTx().message}: ${e instanceof Error ? e.message : String(e)}`)
  }

  if (parsed.inputs.length === 0) {
    throw new Error(`${ErrInvalidTx().message}: pre-signed tx has no inputs`)
  }

  // Verify the pre-signed tx references the expected HTLC funding UTXO.
  const inputTxIDHex = parsed.inputs[0].sourceTXID ?? ''
  const inputVout = parsed.inputs[0].sourceOutputIndex
  if (params.fundingTxID != null && params.fundingTxID.length > 0) {
    const expectedTxIDHex = toHex(params.fundingTxID)
    if (inputTxIDHex !== expectedTxIDHex) {
      throw new Error(
        `${ErrFundingMismatch().message}: input references ${inputTxIDHex}, expected ${expectedTxIDHex}`,
      )
    }
    if (params.fundingVout != null && inputVout !== params.fundingVout) {
      throw new Error(
        `${ErrFundingMismatch().message}: input vout ${inputVout}, expected ${params.fundingVout}`,
      )
    }
  }

  // Rebuild a fresh transaction to avoid @bsv/sdk serialization cache issues.
  // (Transaction.fromBinary caches rawBytes; modifying inputs doesn't invalidate.)
  const tx = new Transaction()
  tx.version = parsed.version
  tx.lockTime = parsed.lockTime

  tx.addInput({
    sourceTXID: inputTxIDHex,
    sourceOutputIndex: inputVout,
    sequence: parsed.inputs[0].sequence ?? 0xfffffffe,
  })

  // Set source transaction for sighash computation.
  const sourceTx = new Transaction()
  for (let v = 0; v < inputVout; v++) {
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
  tx.inputs[0].sourceOutputIndex = inputVout

  // Re-add outputs from parsed tx.
  for (const output of parsed.outputs) {
    tx.addOutput({
      lockingScript: output.lockingScript,
      satoshis: output.satoshis ?? 0,
    })
  }

  // Compute sighash and sign with buyer's key.
  const scope = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID

  const preimage = TransactionSignature.format({
    sourceTXID: inputTxIDHex,
    sourceOutputIndex: inputVout,
    sourceSatoshis: Number(params.fundingAmount),
    transactionVersion: tx.version,
    otherInputs: [],
    outputs: tx.outputs,
    inputIndex: 0,
    subscript: Script.fromBinary(Array.from(params.htlcScript)),
    inputSequence: tx.inputs[0].sequence ?? 0xfffffffe,
    lockTime: tx.lockTime,
    scope,
  })

  const sigHash = Hash.hash256(preimage)
  const sig = params.buyerPrivKey.sign(sigHash)

  const buyerSigBytes: number[] = [...sig.toDER(), scope & 0xff]

  // Build unlocking script: OP_0 <buyer_sig> <seller_sig> OP_FALSE
  // OP_0 is the dummy element required by CHECKMULTISIG (off-by-one bug workaround).
  // OP_FALSE selects the ELSE branch of the HTLC script (refund path).
  const unlockScript = new Script()
  unlockScript.writeOpCode(OP.OP_0)
  unlockScript.writeBin(buyerSigBytes)
  unlockScript.writeBin(Array.from(params.sellerSig))
  unlockScript.writeOpCode(OP.OP_FALSE)

  tx.inputs[0].unlockingScript = UnlockingScript.fromBinary(unlockScript.toBinary())

  return Uint8Array.from(tx.toBinary())
}
