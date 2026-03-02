import { describe, it, expect } from 'vitest'
import { Hash, OP, Script, Transaction, PrivateKey, LockingScript } from '@bsv/sdk'
import {
  buildHTLC,
  buildHTLCFundingTx,
} from '../htlc.js'
import {
  verifyHTLCFunding,
  buildSellerPreSignedRefund,
  buildBuyerRefundTx,
} from '../refund.js'
import type { HTLCParams } from '../types.js'
import {
  DEFAULT_HTLC_TIMEOUT,
  COMPRESSED_PUB_KEY_LEN,
  PUB_KEY_HASH_LEN,
  CAPSULE_HASH_LEN,
} from '../types.js'

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeCapsuleHash(): Uint8Array {
  return Uint8Array.from(Hash.sha256(Array.from(new TextEncoder().encode('refund-test-capsule'))))
}

function makeHTLCScript(buyerPub: Uint8Array, sellerPub: Uint8Array, sellerPKH: Uint8Array): Uint8Array {
  return buildHTLC({
    buyerPubKey: buyerPub,
    sellerPubKey: sellerPub,
    sellerPubKeyHash: sellerPKH,
    capsuleHash: makeCapsuleHash(),
    amount: 10000n,
    timeoutBlocks: DEFAULT_HTLC_TIMEOUT,
  })
}

function buildMockFundingTx(htlcScript: Uint8Array, amount: number): Transaction {
  const tx = new Transaction()
  tx.addOutput({
    lockingScript: LockingScript.fromBinary(Array.from(htlcScript)),
    satoshis: amount,
  })
  return tx
}

// ---------------------------------------------------------------------------
// verifyHTLCFunding tests
// ---------------------------------------------------------------------------

describe('verifyHTLCFunding', () => {
  const sellerPriv = PrivateKey.fromRandom()
  const buyerPriv = PrivateKey.fromRandom()
  const sellerPub = Uint8Array.from(sellerPriv.toPublicKey().toDER())
  const buyerPub = Uint8Array.from(buyerPriv.toPublicKey().toDER())
  const sellerPKH = Uint8Array.from(Hash.hash160(Array.from(sellerPub)))
  const htlcScript = makeHTLCScript(buyerPub, sellerPub, sellerPKH)

  it('finds matching HTLC output', () => {
    const fundingTx = buildMockFundingTx(htlcScript, 10000)
    const rawTx = Uint8Array.from(fundingTx.toBinary())
    const vout = verifyHTLCFunding(rawTx, htlcScript, 10000n)
    expect(vout).toBe(0)
  })

  it('finds HTLC output at non-zero index', () => {
    const tx = new Transaction()
    // Add a dummy P2PKH output first.
    const dummyScript = new Script()
    dummyScript.writeOpCode(OP.OP_DUP)
    dummyScript.writeOpCode(OP.OP_HASH160)
    dummyScript.writeBin(Array.from(new Uint8Array(20)))
    dummyScript.writeOpCode(OP.OP_EQUALVERIFY)
    dummyScript.writeOpCode(OP.OP_CHECKSIG)
    tx.addOutput({
      lockingScript: LockingScript.fromBinary(dummyScript.toBinary()),
      satoshis: 500,
    })
    // Then the HTLC output.
    tx.addOutput({
      lockingScript: LockingScript.fromBinary(Array.from(htlcScript)),
      satoshis: 10000,
    })
    const rawTx = Uint8Array.from(tx.toBinary())
    const vout = verifyHTLCFunding(rawTx, htlcScript, 10000n)
    expect(vout).toBe(1)
  })

  it('accepts overpayment (amount exceeds minimum)', () => {
    const fundingTx = buildMockFundingTx(htlcScript, 20000)
    const rawTx = Uint8Array.from(fundingTx.toBinary())
    const vout = verifyHTLCFunding(rawTx, htlcScript, 10000n)
    expect(vout).toBe(0)
  })

  it('rejects insufficient amount', () => {
    const fundingTx = buildMockFundingTx(htlcScript, 500)
    const rawTx = Uint8Array.from(fundingTx.toBinary())
    expect(() => verifyHTLCFunding(rawTx, htlcScript, 10000n)).toThrow('insufficient')
  })

  it('throws when no matching output', () => {
    // Build a tx with a regular P2PKH output (no HTLC).
    const tx = new Transaction()
    const dummyScript = new Script()
    dummyScript.writeOpCode(OP.OP_DUP)
    dummyScript.writeOpCode(OP.OP_HASH160)
    dummyScript.writeBin(Array.from(new Uint8Array(20)))
    dummyScript.writeOpCode(OP.OP_EQUALVERIFY)
    dummyScript.writeOpCode(OP.OP_CHECKSIG)
    tx.addOutput({
      lockingScript: LockingScript.fromBinary(dummyScript.toBinary()),
      satoshis: 10000,
    })
    const rawTx = Uint8Array.from(tx.toBinary())
    expect(() => verifyHTLCFunding(rawTx, htlcScript, 10000n)).toThrow('no matching output')
  })

  it('throws on empty raw transaction', () => {
    expect(() => verifyHTLCFunding(new Uint8Array(0), htlcScript, 10000n)).toThrow('empty raw transaction')
  })

  it('throws on nil expected script', () => {
    const fundingTx = buildMockFundingTx(htlcScript, 10000)
    const rawTx = Uint8Array.from(fundingTx.toBinary())
    expect(() => verifyHTLCFunding(rawTx, new Uint8Array(0), 10000n)).toThrow('nil expected script')
  })
})

// ---------------------------------------------------------------------------
// Refund round-trip tests
// ---------------------------------------------------------------------------

describe('x402 refund flow', () => {
  it('complete refund round-trip: fund -> pre-sign -> counter-sign', async () => {
    const sellerPriv = PrivateKey.fromRandom()
    const buyerPriv = PrivateKey.fromRandom()
    const sellerPub = Uint8Array.from(sellerPriv.toPublicKey().toDER())
    const buyerPub = Uint8Array.from(buyerPriv.toPublicKey().toDER())
    const sellerPKH = Uint8Array.from(Hash.hash160(Array.from(sellerPub)))
    const buyerPKH = Uint8Array.from(Hash.hash160(Array.from(buyerPub)))
    const capsuleHash = makeCapsuleHash()

    // 1. Build HTLC script.
    const htlcScript = buildHTLC({
      buyerPubKey: buyerPub,
      sellerPubKey: sellerPub,
      sellerPubKeyHash: sellerPKH,
      capsuleHash,
      amount: 10000n,
      timeoutBlocks: DEFAULT_HTLC_TIMEOUT,
    })

    // 2. Create a mock funding UTXO (a transaction with the HTLC output).
    const mockFundingTx = buildMockFundingTx(htlcScript, 10000)
    const mockTxIdHex = mockFundingTx.id('hex')
    // Convert hex txid to internal byte order (reverse bytes).
    const fundingTxID = new Uint8Array(
      mockTxIdHex.match(/.{2}/g)!.map((b: string) => parseInt(b, 16)).reverse(),
    )

    // 3. Seller pre-signs the refund.
    const preSign = await buildSellerPreSignedRefund({
      fundingTxID,
      fundingVout: 0,
      fundingAmount: 10000n,
      htlcScript,
      sellerPrivKey: sellerPriv,
      buyerOutputAddr: buyerPKH,
      timeout: DEFAULT_HTLC_TIMEOUT,
      feeRate: 1,
    })

    expect(preSign.txBytes.length).toBeGreaterThan(0)
    expect(preSign.sellerSig.length).toBeGreaterThan(0)

    // Verify seller pre-signed tx structure.
    const preSignedTx = Transaction.fromBinary(Array.from(preSign.txBytes))
    expect(preSignedTx.lockTime).toBe(DEFAULT_HTLC_TIMEOUT)
    expect(preSignedTx.inputs[0].sequence).toBe(0xfffffffe)

    // 4. Buyer counter-signs.
    const refundRawTx = await buildBuyerRefundTx({
      sellerPreSignedTx: preSign.txBytes,
      sellerSig: preSign.sellerSig,
      htlcScript,
      fundingAmount: 10000n,
      buyerPrivKey: buyerPriv,
      fundingTxID,
      fundingVout: 0,
    })

    expect(refundRawTx.length).toBeGreaterThan(0)

    // 5. Verify the final refund transaction.
    const refundTx = Transaction.fromBinary(Array.from(refundRawTx))

    // nLockTime should match the timeout.
    expect(refundTx.lockTime).toBe(DEFAULT_HTLC_TIMEOUT)

    // Input sequence should enable nLockTime.
    expect(refundTx.inputs[0].sequence).toBe(0xfffffffe)

    // Output should go to buyer's address.
    expect(refundTx.outputs.length).toBe(1)
    const outputAmount = BigInt(refundTx.outputs[0].satoshis ?? 0)
    expect(outputAmount).toBeGreaterThan(0n)
    expect(outputAmount).toBeLessThan(10000n) // Less due to fee.

    // Unlocking script should have 4 chunks: OP_0 <buyer_sig> <seller_sig> OP_FALSE
    const unlockingScript = refundTx.inputs[0].unlockingScript
    expect(unlockingScript).toBeDefined()
    const chunks = unlockingScript!.chunks
    expect(chunks.length).toBe(4)

    // First chunk: OP_0 (CHECKMULTISIG dummy).
    expect(chunks[0].op).toBe(OP.OP_0)

    // Chunks 1 and 2 should be push data (signatures).
    expect(chunks[1].data).toBeDefined()
    expect(chunks[1].data!.length).toBeGreaterThan(0)
    expect(chunks[2].data).toBeDefined()
    expect(chunks[2].data!.length).toBeGreaterThan(0)

    // Last chunk: OP_FALSE (selects ELSE branch).
    expect(chunks[3].op).toBe(OP.OP_0) // OP_FALSE === OP_0
  })

  it('buildBuyerRefundTx rejects mismatched funding txid', async () => {
    const sellerPriv = PrivateKey.fromRandom()
    const buyerPriv = PrivateKey.fromRandom()
    const sellerPub = Uint8Array.from(sellerPriv.toPublicKey().toDER())
    const buyerPub = Uint8Array.from(buyerPriv.toPublicKey().toDER())
    const sellerPKH = Uint8Array.from(Hash.hash160(Array.from(sellerPub)))
    const buyerPKH = Uint8Array.from(Hash.hash160(Array.from(buyerPub)))
    const capsuleHash = makeCapsuleHash()

    const htlcScript = buildHTLC({
      buyerPubKey: buyerPub,
      sellerPubKey: sellerPub,
      sellerPubKeyHash: sellerPKH,
      capsuleHash,
      amount: 10000n,
      timeoutBlocks: DEFAULT_HTLC_TIMEOUT,
    })

    const mockFundingTx = buildMockFundingTx(htlcScript, 10000)
    const mockTxIdHex = mockFundingTx.id('hex')
    const fundingTxID = new Uint8Array(
      mockTxIdHex.match(/.{2}/g)!.map((b: string) => parseInt(b, 16)).reverse(),
    )

    const preSign = await buildSellerPreSignedRefund({
      fundingTxID,
      fundingVout: 0,
      fundingAmount: 10000n,
      htlcScript,
      sellerPrivKey: sellerPriv,
      buyerOutputAddr: buyerPKH,
      timeout: DEFAULT_HTLC_TIMEOUT,
      feeRate: 1,
    })

    // Pass a wrong funding TxID.
    const wrongTxID = new Uint8Array(32).fill(0xff)
    await expect(
      buildBuyerRefundTx({
        sellerPreSignedTx: preSign.txBytes,
        sellerSig: preSign.sellerSig,
        htlcScript,
        fundingAmount: 10000n,
        buyerPrivKey: buyerPriv,
        fundingTxID: wrongTxID,
        fundingVout: 0,
      }),
    ).rejects.toThrow('mismatch')
  })

  it('buildBuyerRefundTx rejects mismatched funding vout', async () => {
    const sellerPriv = PrivateKey.fromRandom()
    const buyerPriv = PrivateKey.fromRandom()
    const sellerPub = Uint8Array.from(sellerPriv.toPublicKey().toDER())
    const buyerPub = Uint8Array.from(buyerPriv.toPublicKey().toDER())
    const sellerPKH = Uint8Array.from(Hash.hash160(Array.from(sellerPub)))
    const buyerPKH = Uint8Array.from(Hash.hash160(Array.from(buyerPub)))
    const capsuleHash = makeCapsuleHash()

    const htlcScript = buildHTLC({
      buyerPubKey: buyerPub,
      sellerPubKey: sellerPub,
      sellerPubKeyHash: sellerPKH,
      capsuleHash,
      amount: 10000n,
      timeoutBlocks: DEFAULT_HTLC_TIMEOUT,
    })

    const mockFundingTx = buildMockFundingTx(htlcScript, 10000)
    const mockTxIdHex = mockFundingTx.id('hex')
    const fundingTxID = new Uint8Array(
      mockTxIdHex.match(/.{2}/g)!.map((b: string) => parseInt(b, 16)).reverse(),
    )

    const preSign = await buildSellerPreSignedRefund({
      fundingTxID,
      fundingVout: 0,
      fundingAmount: 10000n,
      htlcScript,
      sellerPrivKey: sellerPriv,
      buyerOutputAddr: buyerPKH,
      timeout: DEFAULT_HTLC_TIMEOUT,
      feeRate: 1,
    })

    // Correct TxID but wrong vout.
    await expect(
      buildBuyerRefundTx({
        sellerPreSignedTx: preSign.txBytes,
        sellerSig: preSign.sellerSig,
        htlcScript,
        fundingAmount: 10000n,
        buyerPrivKey: buyerPriv,
        fundingTxID,
        fundingVout: 99,
      }),
    ).rejects.toThrow('mismatch')
  })

  it('buildBuyerRefundTx skips check when fundingTxID not provided', async () => {
    const sellerPriv = PrivateKey.fromRandom()
    const buyerPriv = PrivateKey.fromRandom()
    const sellerPub = Uint8Array.from(sellerPriv.toPublicKey().toDER())
    const buyerPub = Uint8Array.from(buyerPriv.toPublicKey().toDER())
    const sellerPKH = Uint8Array.from(Hash.hash160(Array.from(sellerPub)))
    const buyerPKH = Uint8Array.from(Hash.hash160(Array.from(buyerPub)))
    const capsuleHash = makeCapsuleHash()

    const htlcScript = buildHTLC({
      buyerPubKey: buyerPub,
      sellerPubKey: sellerPub,
      sellerPubKeyHash: sellerPKH,
      capsuleHash,
      amount: 10000n,
      timeoutBlocks: DEFAULT_HTLC_TIMEOUT,
    })

    const mockFundingTx = buildMockFundingTx(htlcScript, 10000)
    const mockTxIdHex = mockFundingTx.id('hex')
    const fundingTxID = new Uint8Array(
      mockTxIdHex.match(/.{2}/g)!.map((b: string) => parseInt(b, 16)).reverse(),
    )

    const preSign = await buildSellerPreSignedRefund({
      fundingTxID,
      fundingVout: 0,
      fundingAmount: 10000n,
      htlcScript,
      sellerPrivKey: sellerPriv,
      buyerOutputAddr: buyerPKH,
      timeout: DEFAULT_HTLC_TIMEOUT,
      feeRate: 1,
    })

    // No fundingTxID — should skip check and succeed.
    const refundRawTx = await buildBuyerRefundTx({
      sellerPreSignedTx: preSign.txBytes,
      sellerSig: preSign.sellerSig,
      htlcScript,
      fundingAmount: 10000n,
      buyerPrivKey: buyerPriv,
    })

    expect(refundRawTx.length).toBeGreaterThan(0)
  })

  it('buildSellerPreSignedRefund uses default timeout when 0', async () => {
    const sellerPriv = PrivateKey.fromRandom()
    const buyerPriv = PrivateKey.fromRandom()
    const sellerPub = Uint8Array.from(sellerPriv.toPublicKey().toDER())
    const buyerPub = Uint8Array.from(buyerPriv.toPublicKey().toDER())
    const sellerPKH = Uint8Array.from(Hash.hash160(Array.from(sellerPub)))
    const buyerPKH = Uint8Array.from(Hash.hash160(Array.from(buyerPub)))
    const capsuleHash = makeCapsuleHash()

    const htlcScript = buildHTLC({
      buyerPubKey: buyerPub,
      sellerPubKey: sellerPub,
      sellerPubKeyHash: sellerPKH,
      capsuleHash,
      amount: 10000n,
      timeoutBlocks: DEFAULT_HTLC_TIMEOUT,
    })

    const mockTxID = new Uint8Array(32).fill(0xab)

    const preSign = await buildSellerPreSignedRefund({
      fundingTxID: mockTxID,
      fundingVout: 0,
      fundingAmount: 10000n,
      htlcScript,
      sellerPrivKey: sellerPriv,
      buyerOutputAddr: buyerPKH,
      timeout: 0, // Should default to DEFAULT_HTLC_TIMEOUT.
      feeRate: 1,
    })

    const tx = Transaction.fromBinary(Array.from(preSign.txBytes))
    expect(tx.lockTime).toBe(DEFAULT_HTLC_TIMEOUT)
  })

  it('buildSellerPreSignedRefund rejects nil params', async () => {
    await expect(
      buildSellerPreSignedRefund(null as unknown as Parameters<typeof buildSellerPreSignedRefund>[0]),
    ).rejects.toThrow('nil params')
  })

  it('buildSellerPreSignedRefund rejects short funding txid', async () => {
    const sellerPriv = PrivateKey.fromRandom()
    const buyerPKH = new Uint8Array(PUB_KEY_HASH_LEN)
    await expect(
      buildSellerPreSignedRefund({
        fundingTxID: new Uint8Array(16), // too short
        fundingVout: 0,
        fundingAmount: 10000n,
        htlcScript: new Uint8Array([1, 2, 3]),
        sellerPrivKey: sellerPriv,
        buyerOutputAddr: buyerPKH,
        timeout: DEFAULT_HTLC_TIMEOUT,
        feeRate: 1,
      }),
    ).rejects.toThrow('funding txid must be 32 bytes')
  })

  it('buildSellerPreSignedRefund rejects funding amount too small for fee', async () => {
    const sellerPriv = PrivateKey.fromRandom()
    const buyerPKH = new Uint8Array(PUB_KEY_HASH_LEN)
    await expect(
      buildSellerPreSignedRefund({
        fundingTxID: new Uint8Array(32),
        fundingVout: 0,
        fundingAmount: 1n, // too small for fee
        htlcScript: new Uint8Array([1, 2, 3]),
        sellerPrivKey: sellerPriv,
        buyerOutputAddr: buyerPKH,
        timeout: DEFAULT_HTLC_TIMEOUT,
        feeRate: 1,
      }),
    ).rejects.toThrow('too small for fee')
  })

  it('buildBuyerRefundTx rejects nil params', async () => {
    await expect(
      buildBuyerRefundTx(null as unknown as Parameters<typeof buildBuyerRefundTx>[0]),
    ).rejects.toThrow('nil params')
  })

  it('buildBuyerRefundTx rejects empty seller pre-signed tx', async () => {
    const buyerPriv = PrivateKey.fromRandom()
    await expect(
      buildBuyerRefundTx({
        sellerPreSignedTx: new Uint8Array(0),
        sellerSig: new Uint8Array([1, 2, 3]),
        htlcScript: new Uint8Array([1, 2, 3]),
        fundingAmount: 10000n,
        buyerPrivKey: buyerPriv,
      }),
    ).rejects.toThrow('empty seller pre-signed tx')
  })

  it('buildBuyerRefundTx rejects empty seller signature', async () => {
    const buyerPriv = PrivateKey.fromRandom()
    await expect(
      buildBuyerRefundTx({
        sellerPreSignedTx: new Uint8Array([1, 2, 3]),
        sellerSig: new Uint8Array(0),
        htlcScript: new Uint8Array([1, 2, 3]),
        fundingAmount: 10000n,
        buyerPrivKey: buyerPriv,
      }),
    ).rejects.toThrow('empty seller signature')
  })
})
