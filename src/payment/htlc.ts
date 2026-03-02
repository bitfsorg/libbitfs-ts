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
import type { PrivateKey } from '@bsv/sdk'
import type {
  HTLCParams,
  HTLCFundingParams,
  HTLCFundingResult,
  SellerClaimParams,
} from './types.js'
import {
  DEFAULT_HTLC_TIMEOUT,
  MIN_HTLC_TIMEOUT,
  MAX_HTLC_TIMEOUT,
  COMPRESSED_PUB_KEY_LEN,
  PUB_KEY_HASH_LEN,
  CAPSULE_HASH_LEN,
  INVOICE_ID_LEN,
  DEFAULT_HTLC_FEE_RATE,
} from './types.js'
import {
  ErrHTLCBuildFailed,
  ErrInvalidParams,
  ErrInsufficientPayment,
} from './errors.js'
import { computeCapsuleHash } from '../method42/capsule.js'
import { timingSafeEqual, toHex } from '../util.js'

// ---------------------------------------------------------------------------
// HTLC script building
// ---------------------------------------------------------------------------

/**
 * Constructs an HTLC locking script. When InvoiceID is provided,
 * the script is prefixed with <invoice_id_16> OP_DROP for replay protection,
 * binding the HTLC to a specific invoice:
 *
 *   [<invoice_id_16> OP_DROP]   // optional, present when invoiceID is non-empty
 *   OP_IF
 *     // Seller claim: reveal capsule + seller sig (P2PKH-style)
 *     OP_SHA256 <capsule_hash> OP_EQUALVERIFY
 *     OP_DUP OP_HASH160 <seller_pkh> OP_EQUALVERIFY OP_CHECKSIG
 *   OP_ELSE
 *     // Buyer refund: 2-of-2 multisig (spent via pre-signed refund tx)
 *     OP_2 <buyer_pubkey> <seller_pubkey> OP_2 OP_CHECKMULTISIG
 *   OP_ENDIF
 */
export function buildHTLC(params: HTLCParams): Uint8Array {
  if (params == null) {
    throw new Error(`${ErrHTLCBuildFailed().message}: nil params`)
  }
  if (params.buyerPubKey.length !== COMPRESSED_PUB_KEY_LEN) {
    throw new Error(
      `${ErrHTLCBuildFailed().message}: buyer pubkey must be ${COMPRESSED_PUB_KEY_LEN} bytes, got ${params.buyerPubKey.length}`,
    )
  }
  if (params.sellerPubKey.length !== COMPRESSED_PUB_KEY_LEN) {
    throw new Error(
      `${ErrHTLCBuildFailed().message}: seller pubkey must be ${COMPRESSED_PUB_KEY_LEN} bytes, got ${params.sellerPubKey.length}`,
    )
  }
  if (params.sellerPubKeyHash.length !== PUB_KEY_HASH_LEN) {
    throw new Error(
      `${ErrHTLCBuildFailed().message}: seller address must be ${PUB_KEY_HASH_LEN} bytes, got ${params.sellerPubKeyHash.length}`,
    )
  }
  if (params.capsuleHash.length !== CAPSULE_HASH_LEN) {
    throw new Error(
      `${ErrHTLCBuildFailed().message}: capsule hash must be ${CAPSULE_HASH_LEN} bytes, got ${params.capsuleHash.length}`,
    )
  }
  if (params.amount <= 0n) {
    throw new Error(`${ErrHTLCBuildFailed().message}: amount must be > 0`)
  }
  if (params.timeoutBlocks <= 0) {
    throw new Error(`${ErrHTLCBuildFailed().message}: timeout must be > 0`)
  }
  if (params.timeoutBlocks < MIN_HTLC_TIMEOUT) {
    throw new Error(
      `${ErrHTLCBuildFailed().message}: timeout ${params.timeoutBlocks} below minimum ${MIN_HTLC_TIMEOUT} blocks`,
    )
  }
  if (params.timeoutBlocks > MAX_HTLC_TIMEOUT) {
    throw new Error(
      `${ErrHTLCBuildFailed().message}: timeout ${params.timeoutBlocks} exceeds maximum ${MAX_HTLC_TIMEOUT} blocks`,
    )
  }
  if (params.invoiceID != null && params.invoiceID.length > 0 && params.invoiceID.length !== INVOICE_ID_LEN) {
    throw new Error(
      `${ErrHTLCBuildFailed().message}: invoice ID must be ${INVOICE_ID_LEN} bytes, got ${params.invoiceID.length}`,
    )
  }

  const s = new Script()

  // Optional replay protection prefix: <invoice_id_16> OP_DROP
  if (params.invoiceID != null && params.invoiceID.length === INVOICE_ID_LEN) {
    s.writeBin(Array.from(params.invoiceID))
    s.writeOpCode(OP.OP_DROP)
  }

  // OP_IF
  s.writeOpCode(OP.OP_IF)

  // Seller claim path: OP_SHA256 <capsule_hash> OP_EQUALVERIFY
  s.writeOpCode(OP.OP_SHA256)
  s.writeBin(Array.from(params.capsuleHash))
  s.writeOpCode(OP.OP_EQUALVERIFY)

  // Seller verification: OP_DUP OP_HASH160 <seller_pkh> OP_EQUALVERIFY OP_CHECKSIG
  s.writeOpCode(OP.OP_DUP)
  s.writeOpCode(OP.OP_HASH160)
  s.writeBin(Array.from(params.sellerPubKeyHash))
  s.writeOpCode(OP.OP_EQUALVERIFY)
  s.writeOpCode(OP.OP_CHECKSIG)

  // OP_ELSE
  s.writeOpCode(OP.OP_ELSE)

  // Buyer refund path: OP_2 <buyer_pubkey> <seller_pubkey> OP_2 OP_CHECKMULTISIG
  s.writeOpCode(OP.OP_2)
  s.writeBin(Array.from(params.buyerPubKey))
  s.writeBin(Array.from(params.sellerPubKey))
  s.writeOpCode(OP.OP_2)
  s.writeOpCode(OP.OP_CHECKMULTISIG)

  // OP_ENDIF
  s.writeOpCode(OP.OP_ENDIF)

  return Uint8Array.from(s.toBinary())
}

// ---------------------------------------------------------------------------
// HTLC script parsing
// ---------------------------------------------------------------------------

/**
 * Extracts the capsule hash embedded in an HTLC locking script.
 * Supports both formats:
 *   - Legacy:  OP_IF OP_SHA256 <capsule_hash_32> OP_EQUALVERIFY ...
 *   - With ID: <invoice_id_16> OP_DROP OP_IF OP_SHA256 <capsule_hash_32> OP_EQUALVERIFY ...
 */
export function extractCapsuleHashFromHTLC(scriptBytes: Uint8Array): Uint8Array {
  const s = Script.fromBinary(Array.from(scriptBytes))
  const chunks = s.chunks

  const offset = htlcInvoiceIDOffset(chunks)

  if (chunks.length < offset + 3) {
    throw new Error(`HTLC script too short: ${chunks.length} chunks`)
  }
  if (chunks[offset].op !== OP.OP_IF) {
    throw new Error(`expected OP_IF at position ${offset}, got 0x${chunks[offset].op.toString(16).padStart(2, '0')}`)
  }
  if (chunks[offset + 1].op !== OP.OP_SHA256) {
    throw new Error(
      `expected OP_SHA256 at position ${offset + 1}, got 0x${chunks[offset + 1].op.toString(16).padStart(2, '0')}`,
    )
  }
  const hashData = chunks[offset + 2].data
  if (hashData == null || hashData.length !== CAPSULE_HASH_LEN) {
    throw new Error(
      `capsule hash must be ${CAPSULE_HASH_LEN} bytes, got ${hashData?.length ?? 0}`,
    )
  }
  return Uint8Array.from(hashData)
}

/**
 * Extracts the invoice ID from an HTLC locking script, if present.
 * Returns null if the script uses the legacy format without an invoice ID prefix.
 */
export function extractInvoiceIDFromHTLC(scriptBytes: Uint8Array): Uint8Array | null {
  const s = Script.fromBinary(Array.from(scriptBytes))
  const chunks = s.chunks

  if (chunks.length < 2) {
    return null
  }
  // Check for <16-byte push data> OP_DROP pattern.
  if (chunks[0].data != null && chunks[0].data.length === INVOICE_ID_LEN && chunks[1].op === OP.OP_DROP) {
    return Uint8Array.from(chunks[0].data)
  }
  return null
}

// ---------------------------------------------------------------------------
// HTLC funding transaction
// ---------------------------------------------------------------------------

/**
 * Creates a signed transaction with an HTLC output.
 * Input: buyer's P2PKH UTXOs. Output 0: HTLC script. Output 1: change (if any).
 */
export async function buildHTLCFundingTx(params: HTLCFundingParams): Promise<HTLCFundingResult> {
  if (params == null) {
    throw new Error(`${ErrInvalidParams().message}: nil params`)
  }
  if (params.buyerPrivKey == null) {
    throw new Error(`${ErrInvalidParams().message}: nil buyer private key`)
  }
  if (params.utxos.length === 0) {
    throw new Error(`${ErrInvalidParams().message}: no UTXOs provided`)
  }
  if (params.sellerPubKeyHash.length !== PUB_KEY_HASH_LEN) {
    throw new Error(`${ErrInvalidParams().message}: seller address must be ${PUB_KEY_HASH_LEN} bytes`)
  }
  if (params.sellerPubKey.length !== COMPRESSED_PUB_KEY_LEN) {
    throw new Error(`${ErrInvalidParams().message}: seller pubkey must be ${COMPRESSED_PUB_KEY_LEN} bytes`)
  }
  if (params.capsuleHash.length !== CAPSULE_HASH_LEN) {
    throw new Error(`${ErrInvalidParams().message}: capsule hash must be ${CAPSULE_HASH_LEN} bytes`)
  }
  if (params.changeAddr.length !== PUB_KEY_HASH_LEN) {
    throw new Error(`${ErrInvalidParams().message}: change address must be ${PUB_KEY_HASH_LEN} bytes`)
  }
  if (params.amount <= 0n) {
    throw new Error(`${ErrInvalidParams().message}: amount must be greater than zero`)
  }

  const htlcAmount = params.amount

  let timeout = params.timeout
  if (timeout === 0) {
    timeout = DEFAULT_HTLC_TIMEOUT
  }
  if (timeout < MIN_HTLC_TIMEOUT) {
    throw new Error(`${ErrInvalidParams().message}: timeout ${timeout} below minimum ${MIN_HTLC_TIMEOUT} blocks`)
  }
  if (timeout > MAX_HTLC_TIMEOUT) {
    throw new Error(`${ErrInvalidParams().message}: timeout ${timeout} exceeds maximum ${MAX_HTLC_TIMEOUT} blocks`)
  }

  const feeRate = params.feeRate > 0 ? params.feeRate : DEFAULT_HTLC_FEE_RATE

  // Build the HTLC locking script.
  const buyerPubKey = params.buyerPrivKey.toPublicKey().toDER() as number[]
  const htlcScript = buildHTLC({
    buyerPubKey: Uint8Array.from(buyerPubKey),
    sellerPubKey: params.sellerPubKey,
    sellerPubKeyHash: params.sellerPubKeyHash,
    capsuleHash: params.capsuleHash,
    amount: htlcAmount,
    timeoutBlocks: timeout,
    invoiceID: params.invoiceID,
  })

  // Calculate total input amount.
  let totalInput = 0n
  for (const utxo of params.utxos) {
    totalInput += utxo.amount
  }

  // Estimate fee using actual HTLC script size.
  const htlcOutputSize = 8 + 1 + htlcScript.length    // satoshis + varint + script
  const changeOutputSize = 8 + 1 + 25                  // P2PKH: 8 + varint + OP_DUP..OP_CHECKSIG
  const estSize = 10 + params.utxos.length * 148 + htlcOutputSize + changeOutputSize
  const estFee = BigInt(estSize) * BigInt(feeRate)

  const totalNeeded = htlcAmount + estFee
  if (totalInput < totalNeeded) {
    throw new Error(
      `${ErrInsufficientPayment().message}: have ${totalInput} satoshis, need ${totalNeeded} (amount=${htlcAmount} + fee~${estFee})`,
    )
  }

  // Build the transaction.
  const tx = new Transaction()

  // Add inputs.
  for (const utxo of params.utxos) {
    tx.addInput({
      sourceTXID: toHex(utxo.txID),
      sourceOutputIndex: utxo.vout,
      sequence: 0xffffffff,
    })
  }

  // Output 0: HTLC.
  tx.addOutput({
    lockingScript: LockingScript.fromBinary(Array.from(htlcScript)),
    satoshis: Number(htlcAmount),
  })

  // Output 1: change (if any).
  const changeAmount = totalInput - htlcAmount - estFee
  if (changeAmount > 0n) {
    const p2pkh = new P2PKH()
    const changeLockingScript = p2pkh.lock(Array.from(params.changeAddr))
    tx.addOutput({
      lockingScript: changeLockingScript,
      satoshis: Number(changeAmount),
    })
  }

  // Set source outputs and sign each input.
  const p2pkh = new P2PKH()
  for (let i = 0; i < params.utxos.length; i++) {
    const utxo = params.utxos[i]

    // Create a source transaction for sighash computation.
    const sourceTx = new Transaction()
    for (let v = 0; v < utxo.vout; v++) {
      sourceTx.addOutput({
        lockingScript: LockingScript.fromBinary([]),
        satoshis: 0,
      })
    }
    sourceTx.addOutput({
      lockingScript: LockingScript.fromBinary(Array.from(utxo.scriptPubKey)),
      satoshis: Number(utxo.amount),
    })
    tx.inputs[i].sourceTransaction = sourceTx
    tx.inputs[i].sourceOutputIndex = utxo.vout

    tx.inputs[i].unlockingScriptTemplate = p2pkh.unlock(params.buyerPrivKey)
  }

  await tx.sign()

  const rawTx = Uint8Array.from(tx.toBinary())
  const txIdHex = tx.id('hex')
  const txID = new Uint8Array(txIdHex.match(/.{2}/g)!.map((b: string) => parseInt(b, 16)).reverse())

  return {
    rawTx,
    txID,
    htlcVout: 0,
    htlcScript,
    htlcAmount,
  }
}

// ---------------------------------------------------------------------------
// Seller claim transaction
// ---------------------------------------------------------------------------

/**
 * Creates a signed transaction spending the HTLC via the seller claim path.
 * Unlocking script: <sig+flag> <seller_pubkey> <capsule> OP_TRUE
 *
 * @returns Serialized signed transaction bytes.
 */
export async function buildSellerClaimTx(params: SellerClaimParams): Promise<Uint8Array> {
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
  if (params.capsule.length === 0) {
    throw new Error(`${ErrInvalidParams().message}: empty capsule`)
  }
  if (params.outputAddr.length !== PUB_KEY_HASH_LEN) {
    throw new Error(`${ErrInvalidParams().message}: output address must be ${PUB_KEY_HASH_LEN} bytes`)
  }

  // Verify capsule matches the hash embedded in the HTLC script.
  const capsuleHashFromScript = extractCapsuleHashFromHTLC(params.htlcScript)
  const computedHash = computeCapsuleHash(params.fileTxID, params.capsule)
  if (computedHash == null || !timingSafeEqual(computedHash, capsuleHashFromScript)) {
    throw new Error(`${ErrInvalidParams().message}: capsule hash mismatch`)
  }

  const feeRate = params.feeRate > 0 ? params.feeRate : DEFAULT_HTLC_FEE_RATE

  // Estimate claim tx size: ~10 overhead + ~(73+33+32+1) unlocking + script + ~40 output.
  const estSize = 10 + 73 + 33 + 32 + 1 + params.htlcScript.length + 40
  const estFee = BigInt(estSize) * BigInt(feeRate)

  if (params.fundingAmount <= estFee) {
    throw new Error(
      `${ErrInsufficientPayment().message}: funding amount ${params.fundingAmount} too small for fee ${estFee}`,
    )
  }

  const outputAmount = params.fundingAmount - estFee
  const fundingTxIDHex = toHex(params.fundingTxID)

  const tx = new Transaction()

  tx.addInput({
    sourceTXID: fundingTxIDHex,
    sourceOutputIndex: params.fundingVout,
    sequence: 0xffffffff,
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

  // Output: P2PKH to seller.
  const p2pkh = new P2PKH()
  const outputScript = p2pkh.lock(Array.from(params.outputAddr))
  tx.addOutput({
    lockingScript: outputScript,
    satoshis: Number(outputAmount),
  })

  // Compute sighash manually for the custom HTLC script.
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
    inputSequence: 0xffffffff,
    lockTime: tx.lockTime,
    scope,
  })

  const sigHash = Hash.hash256(preimage)
  const sig = params.sellerPrivKey.sign(sigHash)

  // Build unlocking script: <sig+flag> <seller_pubkey> <capsule> OP_TRUE
  const sigBytes: number[] = [...(sig.toDER() as number[]), scope & 0xff]
  const sellerPubKey = params.sellerPrivKey.toPublicKey().toDER() as number[]

  const unlockScript = new Script()
  unlockScript.writeBin(sigBytes)
  unlockScript.writeBin(sellerPubKey)
  unlockScript.writeBin(Array.from(params.capsule))
  unlockScript.writeOpCode(OP.OP_TRUE)

  tx.inputs[0].unlockingScript = UnlockingScript.fromBinary(unlockScript.toBinary())

  return Uint8Array.from(tx.toBinary())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Determine the chunk offset to skip the optional <invoice_id_16> OP_DROP prefix. */
function htlcInvoiceIDOffset(chunks: Array<{ op: number; data?: number[] }>): number {
  if (
    chunks.length >= 2 &&
    chunks[0].data != null &&
    chunks[0].data.length === INVOICE_ID_LEN &&
    chunks[1].op === OP.OP_DROP
  ) {
    return 2
  }
  return 0
}

