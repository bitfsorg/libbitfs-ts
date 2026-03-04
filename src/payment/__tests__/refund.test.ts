import { describe, it, expect } from 'vitest'
import { Hash, OP, Script, Transaction, PrivateKey, LockingScript } from '@bsv/sdk'
import {
  buildHTLC,
} from '../htlc.js'
import {
  verifyHTLCFunding,
  buildBuyerRefundTx,
} from '../refund.js'
import type { BuyerRefundParams } from '../types.js'
import {
  DEFAULT_HTLC_TIMEOUT,
  PUB_KEY_HASH_LEN,
  INVOICE_ID_LEN,
} from '../types.js'

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeCapsuleHash(): Uint8Array {
  return Uint8Array.from(Hash.sha256(Array.from(new TextEncoder().encode('refund-test-capsule'))))
}

function makeInvoiceID(): Uint8Array {
  const id = new Uint8Array(INVOICE_ID_LEN)
  for (let i = 0; i < INVOICE_ID_LEN; i++) id[i] = i + 0xf0
  return id
}

function makeHTLCScript(buyerPub: Uint8Array, sellerPub: Uint8Array, sellerPKH: Uint8Array): Uint8Array {
  return buildHTLC({
    buyerPubKey: buyerPub,
    sellerPubKey: sellerPub,
    sellerPubKeyHash: sellerPKH,
    capsuleHash: makeCapsuleHash(),
    amount: 10000n,
    timeoutBlocks: DEFAULT_HTLC_TIMEOUT,
    invoiceID: makeInvoiceID(),
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
// On-chain buyer refund tests
// ---------------------------------------------------------------------------

describe('buildBuyerRefundTx (on-chain buyer-only)', () => {
  const sellerPriv = PrivateKey.fromRandom()
  const buyerPriv = PrivateKey.fromRandom()
  const sellerPub = Uint8Array.from(sellerPriv.toPublicKey().toDER())
  const buyerPub = Uint8Array.from(buyerPriv.toPublicKey().toDER())
  const sellerPKH = Uint8Array.from(Hash.hash160(Array.from(sellerPub)))
  const buyerPKH = Uint8Array.from(Hash.hash160(Array.from(buyerPub)))
  const htlcScript = makeHTLCScript(buyerPub, sellerPub, sellerPKH)

  it('valid on-chain buyer refund', () => {
    const refundRawTx = buildBuyerRefundTx({
      fundingTxID: new Uint8Array(32).fill(0xab),
      fundingVout: 0,
      fundingAmount: 50000n,
      htlcScript,
      buyerPrivKey: buyerPriv,
      outputAddr: buyerPKH,
      timeout: DEFAULT_HTLC_TIMEOUT,
      feeRate: 1,
    })

    expect(refundRawTx.length).toBeGreaterThan(0)

    const refundTx = Transaction.fromBinary(Array.from(refundRawTx))

    // nLockTime should match the timeout.
    expect(refundTx.lockTime).toBe(DEFAULT_HTLC_TIMEOUT)

    // Input sequence should enable nLockTime (< 0xffffffff).
    expect(refundTx.inputs[0].sequence).toBe(0xfffffffe)

    // Single output to buyer.
    expect(refundTx.outputs.length).toBe(1)
    const outputAmount = BigInt(refundTx.outputs[0].satoshis ?? 0)
    expect(outputAmount).toBeGreaterThan(0n)
    expect(outputAmount).toBeLessThan(50000n) // Less due to fee.

    // Unlocking script should have 3 chunks: <sig> <pubkey> OP_FALSE
    const unlockingScript = refundTx.inputs[0].unlockingScript
    expect(unlockingScript).toBeDefined()
    const chunks = unlockingScript!.chunks
    expect(chunks.length).toBe(3)

    // Chunk 0: buyer signature (push data).
    expect(chunks[0].data).toBeDefined()
    expect(chunks[0].data!.length).toBeGreaterThan(0)

    // Chunk 1: buyer public key (push data, 33 bytes compressed).
    expect(chunks[1].data).toBeDefined()
    expect(chunks[1].data!.length).toBe(33)

    // Chunk 2: OP_0/OP_FALSE (selects ELSE branch for refund).
    expect(chunks[2].op).toBe(OP.OP_0)
  })

  it('uses default timeout when 0', () => {
    const refundRawTx = buildBuyerRefundTx({
      fundingTxID: new Uint8Array(32).fill(0xab),
      fundingVout: 0,
      fundingAmount: 50000n,
      htlcScript,
      buyerPrivKey: buyerPriv,
      outputAddr: buyerPKH,
      timeout: 0,
      feeRate: 1,
    })

    const refundTx = Transaction.fromBinary(Array.from(refundRawTx))
    expect(refundTx.lockTime).toBe(DEFAULT_HTLC_TIMEOUT)
  })

  it('uses custom timeout', () => {
    const refundRawTx = buildBuyerRefundTx({
      fundingTxID: new Uint8Array(32).fill(0xab),
      fundingVout: 0,
      fundingAmount: 50000n,
      htlcScript,
      buyerPrivKey: buyerPriv,
      outputAddr: buyerPKH,
      timeout: 100,
      feeRate: 1,
    })

    const refundTx = Transaction.fromBinary(Array.from(refundRawTx))
    expect(refundTx.lockTime).toBe(100)
  })

  it('uses default fee rate when not specified', () => {
    const refundRawTx = buildBuyerRefundTx({
      fundingTxID: new Uint8Array(32).fill(0xab),
      fundingVout: 0,
      fundingAmount: 50000n,
      htlcScript,
      buyerPrivKey: buyerPriv,
      outputAddr: buyerPKH,
      timeout: DEFAULT_HTLC_TIMEOUT,
    })

    expect(refundRawTx.length).toBeGreaterThan(0)
    const refundTx = Transaction.fromBinary(Array.from(refundRawTx))
    // Output should reflect default sat/KB fee rate fallback.
    const outputAmount = BigInt(refundTx.outputs[0].satoshis ?? 0)
    expect(outputAmount).toBeGreaterThan(0n)
    expect(outputAmount).toBeLessThan(50000n)
  })

  it('handles non-zero fundingVout', () => {
    const refundRawTx = buildBuyerRefundTx({
      fundingTxID: new Uint8Array(32).fill(0xab),
      fundingVout: 2,
      fundingAmount: 50000n,
      htlcScript,
      buyerPrivKey: buyerPriv,
      outputAddr: buyerPKH,
      timeout: DEFAULT_HTLC_TIMEOUT,
      feeRate: 1,
    })

    expect(refundRawTx.length).toBeGreaterThan(0)
    const refundTx = Transaction.fromBinary(Array.from(refundRawTx))
    expect(refundTx.inputs[0].sourceOutputIndex).toBe(2)
  })

  // -------------------------------------------------------------------------
  // Error cases
  // -------------------------------------------------------------------------

  it('rejects nil params', () => {
    expect(() =>
      buildBuyerRefundTx(null as unknown as BuyerRefundParams),
    ).toThrow('nil params')
  })

  it('rejects nil buyer private key', () => {
    expect(() =>
      buildBuyerRefundTx({
        fundingTxID: new Uint8Array(32),
        fundingVout: 0,
        fundingAmount: 50000n,
        htlcScript,
        buyerPrivKey: null as unknown as PrivateKey,
        outputAddr: buyerPKH,
        timeout: DEFAULT_HTLC_TIMEOUT,
      } as BuyerRefundParams),
    ).toThrow('nil buyer private key')
  })

  it('rejects short funding txid', () => {
    expect(() =>
      buildBuyerRefundTx({
        fundingTxID: new Uint8Array(16), // too short
        fundingVout: 0,
        fundingAmount: 50000n,
        htlcScript,
        buyerPrivKey: buyerPriv,
        outputAddr: buyerPKH,
        timeout: DEFAULT_HTLC_TIMEOUT,
      }),
    ).toThrow('funding txid must be 32 bytes')
  })

  it('rejects empty HTLC script', () => {
    expect(() =>
      buildBuyerRefundTx({
        fundingTxID: new Uint8Array(32),
        fundingVout: 0,
        fundingAmount: 50000n,
        htlcScript: new Uint8Array(0),
        buyerPrivKey: buyerPriv,
        outputAddr: buyerPKH,
        timeout: DEFAULT_HTLC_TIMEOUT,
      }),
    ).toThrow('empty HTLC script')
  })

  it('rejects invalid output address length', () => {
    expect(() =>
      buildBuyerRefundTx({
        fundingTxID: new Uint8Array(32),
        fundingVout: 0,
        fundingAmount: 50000n,
        htlcScript,
        buyerPrivKey: buyerPriv,
        outputAddr: new Uint8Array(10), // wrong length
        timeout: DEFAULT_HTLC_TIMEOUT,
      }),
    ).toThrow(`output address must be ${PUB_KEY_HASH_LEN} bytes`)
  })

  it('rejects zero funding amount', () => {
    expect(() =>
      buildBuyerRefundTx({
        fundingTxID: new Uint8Array(32),
        fundingVout: 0,
        fundingAmount: 0n,
        htlcScript,
        buyerPrivKey: buyerPriv,
        outputAddr: buyerPKH,
        timeout: DEFAULT_HTLC_TIMEOUT,
      }),
    ).toThrow('funding amount must be greater than zero')
  })

  it('rejects funding amount too small for fee', () => {
    expect(() =>
      buildBuyerRefundTx({
        fundingTxID: new Uint8Array(32),
        fundingVout: 0,
        fundingAmount: 10n, // too small for estimated default fee
        htlcScript,
        buyerPrivKey: buyerPriv,
        outputAddr: buyerPKH,
        timeout: DEFAULT_HTLC_TIMEOUT,
      }),
    ).toThrow('too small for fee')
  })

  it('rejects timeout below minimum', () => {
    expect(() =>
      buildBuyerRefundTx({
        fundingTxID: new Uint8Array(32),
        fundingVout: 0,
        fundingAmount: 50000n,
        htlcScript,
        buyerPrivKey: buyerPriv,
        outputAddr: buyerPKH,
        timeout: 1, // below MinHTLCTimeout
      }),
    ).toThrow('below minimum')
  })

  it('rejects timeout above maximum', () => {
    expect(() =>
      buildBuyerRefundTx({
        fundingTxID: new Uint8Array(32),
        fundingVout: 0,
        fundingAmount: 50000n,
        htlcScript,
        buyerPrivKey: buyerPriv,
        outputAddr: buyerPKH,
        timeout: 999999, // above MaxHTLCTimeout
      }),
    ).toThrow('exceeds maximum')
  })
})
