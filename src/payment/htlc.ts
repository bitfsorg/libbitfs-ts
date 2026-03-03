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
import {
  instantiateHTLC,
  isArtifactScript,
  HTLC_INVOICE_ID_OFFSET,
  HTLC_CAPSULE_HASH_OFFSET,
  HTLC_MIN_SCRIPT_LEN,
} from './artifact.js'

// ---------------------------------------------------------------------------
// HTLC script building
// ---------------------------------------------------------------------------

/**
 * Constructs an HTLC locking script by instantiating the compiled sCrypt
 * BitfsHTLC artifact. The artifact encodes both the seller-claim path
 * (hash-lock + P2PKH) and the buyer-refund path (OP_PUSH_TX + nLockTime
 * CLTV) in a single script. Constructor parameters embedded:
 *
 *   - invoiceId   -- 16-byte replay protection token (mandatory)
 *   - capsuleHash -- SHA256(capsule), 32 bytes
 *   - sellerPkh   -- HASH160(seller public key), 20 bytes
 *   - buyerPkh    -- HASH160(buyer public key), 20 bytes
 *   - timeout     -- refund timeout in blocks
 *
 * The seller claims by providing the capsule preimage and their signature.
 * The buyer refunds on-chain after timeout using OP_PUSH_TX to verify nLockTime.
 */
export function buildHTLC(params: HTLCParams): Uint8Array {
  if (params == null) {
    throw new Error(`${ErrHTLCBuildFailed().message}: nil params`)
  }
  if (params.invoiceID.length !== INVOICE_ID_LEN) {
    throw new Error(
      `${ErrHTLCBuildFailed().message}: invoiceID is mandatory (${INVOICE_ID_LEN} bytes), got ${params.invoiceID.length}`,
    )
  }
  if (params.buyerPubKey.length !== COMPRESSED_PUB_KEY_LEN) {
    throw new Error(
      `${ErrHTLCBuildFailed().message}: buyer pubkey must be ${COMPRESSED_PUB_KEY_LEN} bytes, got ${params.buyerPubKey.length}`,
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

  // Derive buyer PKH from buyer public key.
  const buyerPkh = Uint8Array.from(Hash.hash160(Array.from(params.buyerPubKey)))

  return instantiateHTLC(
    params.invoiceID,
    params.capsuleHash,
    params.sellerPubKeyHash,
    buyerPkh,
    params.timeoutBlocks,
  )
}

// ---------------------------------------------------------------------------
// HTLC script parsing
// ---------------------------------------------------------------------------

/**
 * Extracts the 32-byte capsule hash embedded in an HTLC locking script
 * produced by the sCrypt BitfsHTLC artifact. Uses fixed byte offsets
 * determined by the compiled artifact layout.
 */
export function extractCapsuleHashFromHTLC(scriptBytes: Uint8Array): Uint8Array {
  if (scriptBytes.length < HTLC_MIN_SCRIPT_LEN) {
    throw new Error(`HTLC script too short: ${scriptBytes.length} bytes`)
  }
  if (!isArtifactScript(scriptBytes)) {
    throw new Error('HTLC script does not match sCrypt artifact prefix')
  }
  return scriptBytes.slice(HTLC_CAPSULE_HASH_OFFSET, HTLC_CAPSULE_HASH_OFFSET + CAPSULE_HASH_LEN)
}

/**
 * Extracts the 16-byte invoice ID embedded in an HTLC locking script
 * produced by the sCrypt BitfsHTLC artifact. Returns null if the script
 * does not match the expected artifact format.
 */
export function extractInvoiceIDFromHTLC(scriptBytes: Uint8Array): Uint8Array | null {
  if (scriptBytes.length < HTLC_MIN_SCRIPT_LEN) {
    return null // Too short; cannot be an artifact script.
  }
  if (!isArtifactScript(scriptBytes)) {
    return null // Not an artifact script.
  }
  return scriptBytes.slice(HTLC_INVOICE_ID_OFFSET, HTLC_INVOICE_ID_OFFSET + INVOICE_ID_LEN)
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
 * For the sCrypt artifact, the unlocking script for claim (method index 0) is:
 *   <capsule> <sig+flag> <seller_pubkey> OP_0
 *
 * Where OP_0 selects the claim method (index 0).
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

  // Build unlocking script for sCrypt claim path:
  // <capsule> <sig+flag> <seller_pubkey> OP_0
  // OP_0 is the method selector (claim has index 0).
  const sigBytes: number[] = [...(sig.toDER() as number[]), scope & 0xff]
  const sellerPubKey = params.sellerPrivKey.toPublicKey().toDER() as number[]

  const unlockScript = new Script()
  unlockScript.writeBin(Array.from(params.capsule))
  unlockScript.writeBin(sigBytes)
  unlockScript.writeBin(sellerPubKey)
  unlockScript.writeOpCode(OP.OP_0)

  tx.inputs[0].unlockingScript = UnlockingScript.fromBinary(unlockScript.toBinary())

  return Uint8Array.from(tx.toBinary())
}
