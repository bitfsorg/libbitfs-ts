import { describe, it, expect } from 'vitest'
import { Hash, OP, Script, Transaction, PrivateKey, UnlockingScript, LockingScript } from '@bsv/sdk'
import {
  buildHTLC,
  extractCapsuleHashFromHTLC,
  extractInvoiceIDFromHTLC,
} from '../htlc.js'
import { verifyPayment, parseHTLCPreimage } from '../verify.js'
import {
  buildHTLCScript,
  isHTLCScript,
  HTLC_INVOICE_ID_OFFSET,
  HTLC_CAPSULE_HASH_OFFSET,
  HTLC_SELLER_PKH_OFFSET,
  HTLC_BUYER_PKH_OFFSET,
  HTLC_MIN_SCRIPT_LEN,
} from '../artifact.js'
import type { HTLCParams, Invoice, PaymentProof } from '../types.js'
import {
  DEFAULT_HTLC_TIMEOUT,
  MIN_HTLC_TIMEOUT,
  MAX_HTLC_TIMEOUT,
  COMPRESSED_PUB_KEY_LEN,
  PUB_KEY_HASH_LEN,
  CAPSULE_HASH_LEN,
  INVOICE_ID_LEN,
} from '../types.js'
import { toHex, hexToBytes } from '../../util.js'

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeBuyerPubKey(): Uint8Array {
  const k = new Uint8Array(COMPRESSED_PUB_KEY_LEN)
  k[0] = 0x02
  for (let i = 1; i < COMPRESSED_PUB_KEY_LEN; i++) k[i] = i
  return k
}

function makeSellerPubKey(): Uint8Array {
  const k = new Uint8Array(COMPRESSED_PUB_KEY_LEN)
  k[0] = 0x03
  for (let i = 1; i < COMPRESSED_PUB_KEY_LEN; i++) k[i] = i + 50
  return k
}

function makeSellerPKH(): Uint8Array {
  const k = new Uint8Array(PUB_KEY_HASH_LEN)
  for (let i = 0; i < PUB_KEY_HASH_LEN; i++) k[i] = i + 100
  return k
}

function makeCapsuleHash(): Uint8Array {
  return Uint8Array.from(Hash.sha256(Array.from(new TextEncoder().encode('test-capsule'))))
}

function makeInvoiceID(): Uint8Array {
  const id = new Uint8Array(INVOICE_ID_LEN)
  for (let i = 0; i < INVOICE_ID_LEN; i++) id[i] = i + 200
  return id
}

function validHTLCParams(): HTLCParams {
  return {
    buyerPubKey: makeBuyerPubKey(),
    sellerPubKey: makeSellerPubKey(),
    sellerPubKeyHash: makeSellerPKH(),
    capsuleHash: makeCapsuleHash(),
    amount: 1000n,
    timeoutBlocks: DEFAULT_HTLC_TIMEOUT,
    invoiceID: makeInvoiceID(),
  }
}

// ---------------------------------------------------------------------------
// buildHTLCScript tests
// ---------------------------------------------------------------------------

describe('buildHTLCScript', () => {
  it('produces a non-empty script', () => {
    const invoiceId = new Uint8Array(INVOICE_ID_LEN)
    const capsuleHash = new Uint8Array(CAPSULE_HASH_LEN)
    const sellerPkh = new Uint8Array(PUB_KEY_HASH_LEN)
    const buyerPkh = new Uint8Array(PUB_KEY_HASH_LEN)
    const script = buildHTLCScript(invoiceId, capsuleHash, sellerPkh, buyerPkh)
    expect(script.length).toBeGreaterThan(0)
  })

  it('embeds parameters at correct byte offsets', () => {
    const invoiceId = new Uint8Array(INVOICE_ID_LEN)
    for (let i = 0; i < INVOICE_ID_LEN; i++) invoiceId[i] = i + 1
    const capsuleHash = new Uint8Array(CAPSULE_HASH_LEN).fill(0xaa)
    const sellerPkh = new Uint8Array(PUB_KEY_HASH_LEN).fill(0xbb)
    const buyerPkh = new Uint8Array(PUB_KEY_HASH_LEN).fill(0xcc)

    const script = buildHTLCScript(invoiceId, capsuleHash, sellerPkh, buyerPkh)

    // Check invoiceId at offset 1
    const embeddedInvoice = script.slice(HTLC_INVOICE_ID_OFFSET, HTLC_INVOICE_ID_OFFSET + INVOICE_ID_LEN)
    expect(embeddedInvoice).toEqual(invoiceId)

    // Check capsuleHash at offset 21
    const embeddedHash = script.slice(HTLC_CAPSULE_HASH_OFFSET, HTLC_CAPSULE_HASH_OFFSET + CAPSULE_HASH_LEN)
    expect(embeddedHash).toEqual(capsuleHash)

    // Check sellerPkh at offset 57
    const embeddedSeller = script.slice(HTLC_SELLER_PKH_OFFSET, HTLC_SELLER_PKH_OFFSET + PUB_KEY_HASH_LEN)
    expect(embeddedSeller).toEqual(sellerPkh)
  })

  it('is deterministic', () => {
    const invoiceId = new Uint8Array(INVOICE_ID_LEN)
    const capsuleHash = new Uint8Array(CAPSULE_HASH_LEN)
    const sellerPkh = new Uint8Array(PUB_KEY_HASH_LEN)
    const buyerPkh = new Uint8Array(PUB_KEY_HASH_LEN)

    const script1 = buildHTLCScript(invoiceId, capsuleHash, sellerPkh, buyerPkh)
    const script2 = buildHTLCScript(invoiceId, capsuleHash, sellerPkh, buyerPkh)
    expect(script1).toEqual(script2)
  })

  it('throws on wrong invoiceId length', () => {
    expect(() =>
      buildHTLCScript(
        new Uint8Array(10),
        new Uint8Array(CAPSULE_HASH_LEN),
        new Uint8Array(PUB_KEY_HASH_LEN),
        new Uint8Array(PUB_KEY_HASH_LEN),
      ),
    ).toThrow('invoiceId')
  })

  it('throws on wrong capsuleHash length', () => {
    expect(() =>
      buildHTLCScript(
        new Uint8Array(INVOICE_ID_LEN),
        new Uint8Array(16),
        new Uint8Array(PUB_KEY_HASH_LEN),
        new Uint8Array(PUB_KEY_HASH_LEN),
      ),
    ).toThrow('capsuleHash')
  })

  it('throws on wrong sellerPkh length', () => {
    expect(() =>
      buildHTLCScript(
        new Uint8Array(INVOICE_ID_LEN),
        new Uint8Array(CAPSULE_HASH_LEN),
        new Uint8Array(10),
        new Uint8Array(PUB_KEY_HASH_LEN),
      ),
    ).toThrow('sellerPkh')
  })

  it('throws on wrong buyerPkh length', () => {
    expect(() =>
      buildHTLCScript(
        new Uint8Array(INVOICE_ID_LEN),
        new Uint8Array(CAPSULE_HASH_LEN),
        new Uint8Array(PUB_KEY_HASH_LEN),
        new Uint8Array(10),
      ),
    ).toThrow('buyerPkh')
  })

  it('produces correct structural check bytes', () => {
    const invoiceId = new Uint8Array(INVOICE_ID_LEN)
    const capsuleHash = new Uint8Array(CAPSULE_HASH_LEN)
    const sellerPkh = new Uint8Array(PUB_KEY_HASH_LEN)
    const buyerPkh = new Uint8Array(PUB_KEY_HASH_LEN)
    const script = buildHTLCScript(invoiceId, capsuleHash, sellerPkh, buyerPkh)

    expect(script[0]).toBe(0x10)   // PUSH 16 bytes
    expect(script[17]).toBe(0x75)  // OP_DROP
    expect(script[18]).toBe(0x63)  // OP_IF
    expect(script[19]).toBe(0xa8)  // OP_SHA256
    expect(script[20]).toBe(0x20)  // PUSH 32 bytes
  })
})

// ---------------------------------------------------------------------------
// isHTLCScript tests
// ---------------------------------------------------------------------------

describe('isHTLCScript', () => {
  it('identifies HTLC scripts', () => {
    const params = validHTLCParams()
    const script = buildHTLC(params)
    expect(isHTLCScript(script)).toBe(true)
  })

  it('rejects non-HTLC scripts', () => {
    expect(isHTLCScript(new Uint8Array([0x63, 0xa8]))).toBe(false)
  })

  it('rejects empty scripts', () => {
    expect(isHTLCScript(new Uint8Array(0))).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// buildHTLC tests
// ---------------------------------------------------------------------------

describe('buildHTLC', () => {
  it('produces a valid HTLC script', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)
    expect(scriptBytes.length).toBe(HTLC_MIN_SCRIPT_LEN)

    // Should be identified as an HTLC script
    expect(isHTLCScript(scriptBytes)).toBe(true)

    // The capsule hash should be at the expected byte offset
    const embedded = scriptBytes.slice(
      HTLC_CAPSULE_HASH_OFFSET,
      HTLC_CAPSULE_HASH_OFFSET + CAPSULE_HASH_LEN,
    )
    expect(embedded).toEqual(params.capsuleHash)
  })

  it('embeds invoice ID at correct byte offset', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)

    const embedded = scriptBytes.slice(
      HTLC_INVOICE_ID_OFFSET,
      HTLC_INVOICE_ID_OFFSET + INVOICE_ID_LEN,
    )
    expect(embedded).toEqual(params.invoiceID)
  })

  it('embeds seller PKH at correct byte offset', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)

    const embedded = scriptBytes.slice(
      HTLC_SELLER_PKH_OFFSET,
      HTLC_SELLER_PKH_OFFSET + PUB_KEY_HASH_LEN,
    )
    expect(embedded).toEqual(params.sellerPubKeyHash)
  })

  // --- Error cases ---

  it('throws on null params', () => {
    expect(() => buildHTLC(null as unknown as HTLCParams)).toThrow('nil params')
  })

  it('throws on invalid buyer pubkey length', () => {
    const params = validHTLCParams()
    params.buyerPubKey = new Uint8Array([0x02, 0x01])
    expect(() => buildHTLC(params)).toThrow('buyer pubkey must be 33 bytes')
  })

  it('throws on invalid seller address length', () => {
    const params = validHTLCParams()
    params.sellerPubKeyHash = new Uint8Array([0x01, 0x02])
    expect(() => buildHTLC(params)).toThrow('seller address must be 20 bytes')
  })

  it('throws on invalid capsule hash length', () => {
    const params = validHTLCParams()
    params.capsuleHash = new Uint8Array([0x01])
    expect(() => buildHTLC(params)).toThrow('capsule hash must be 32 bytes')
  })

  it('throws on zero amount', () => {
    const params = validHTLCParams()
    params.amount = 0n
    expect(() => buildHTLC(params)).toThrow('amount must be > 0')
  })

  it('throws on zero timeout', () => {
    const params = validHTLCParams()
    params.timeoutBlocks = 0
    expect(() => buildHTLC(params)).toThrow('timeout must be > 0')
  })

  it('throws on timeout below minimum', () => {
    const params = validHTLCParams()
    params.timeoutBlocks = MIN_HTLC_TIMEOUT - 1
    expect(() => buildHTLC(params)).toThrow(`timeout ${MIN_HTLC_TIMEOUT - 1} below minimum ${MIN_HTLC_TIMEOUT}`)
  })

  it('throws on timeout above maximum', () => {
    const params = validHTLCParams()
    params.timeoutBlocks = MAX_HTLC_TIMEOUT + 1
    expect(() => buildHTLC(params)).toThrow(`timeout ${MAX_HTLC_TIMEOUT + 1} exceeds maximum ${MAX_HTLC_TIMEOUT}`)
  })

  it('throws on invalid invoice ID length', () => {
    const params = validHTLCParams()
    params.invoiceID = new Uint8Array(8) // wrong length
    expect(() => buildHTLC(params)).toThrow('invoiceID is mandatory (16 bytes)')
  })
})

// ---------------------------------------------------------------------------
// extractCapsuleHashFromHTLC tests
// ---------------------------------------------------------------------------

describe('extractCapsuleHashFromHTLC', () => {
  it('extracts capsule hash from HTLC script', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)
    const extracted = extractCapsuleHashFromHTLC(scriptBytes)
    expect(extracted).toEqual(params.capsuleHash)
  })

  it('throws on script too short', () => {
    expect(() => extractCapsuleHashFromHTLC(new Uint8Array(10))).toThrow('too short')
  })

  it('throws on non-HTLC script', () => {
    // Create a large enough but non-matching script
    const fake = new Uint8Array(HTLC_MIN_SCRIPT_LEN + 10).fill(0x63)
    expect(() => extractCapsuleHashFromHTLC(fake)).toThrow('does not match')
  })
})

// ---------------------------------------------------------------------------
// extractInvoiceIDFromHTLC tests
// ---------------------------------------------------------------------------

describe('extractInvoiceIDFromHTLC', () => {
  it('extracts invoice ID from HTLC script', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)
    const extracted = extractInvoiceIDFromHTLC(scriptBytes)

    expect(extracted).not.toBeNull()
    expect(extracted).toEqual(params.invoiceID)
  })

  it('returns null for empty script', () => {
    expect(extractInvoiceIDFromHTLC(new Uint8Array(0))).toBeNull()
  })

  it('returns null for non-HTLC script', () => {
    const fake = new Uint8Array(HTLC_MIN_SCRIPT_LEN + 10).fill(0x63)
    expect(extractInvoiceIDFromHTLC(fake)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// verifyPayment tests
// ---------------------------------------------------------------------------

describe('verifyPayment', () => {
  const targetAddr = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'

  function buildPaymentTx(addr: string, satoshis: number): Uint8Array {
    const tx = new Transaction()
    // Use a P2PKH locking script for the target address.
    // Decode address manually to PKH and build the script.
    const pkh = addressToBytes(addr)
    const script = new Script()
    script.writeOpCode(OP.OP_DUP)
    script.writeOpCode(OP.OP_HASH160)
    script.writeBin(pkh)
    script.writeOpCode(OP.OP_EQUALVERIFY)
    script.writeOpCode(OP.OP_CHECKSIG)
    tx.addOutput({
      lockingScript: LockingScript.fromBinary(script.toBinary()),
      satoshis,
    })
    return Uint8Array.from(tx.toBinary())
  }

  it('succeeds for valid payment', () => {
    const rawTx = buildPaymentTx(targetAddr, 1000)
    const inv: Invoice = {
      id: 'test',
      price: 1000n,
      pricePerKB: 50n,
      fileSize: 20480n,
      paymentAddr: targetAddr,
      capsuleHash: new Uint8Array(32),
      expiry: Math.floor(Date.now() / 1000) + 3600,
    }
    const proof: PaymentProof = {
      rawTx,
      invoiceID: new Uint8Array(16),
    }
    const txid = verifyPayment(proof, inv)
    expect(txid).toBeDefined()
    expect(txid.length).toBeGreaterThan(0)
  })

  it('succeeds for overpayment', () => {
    const rawTx = buildPaymentTx(targetAddr, 2000)
    const inv: Invoice = {
      id: 'test',
      price: 1000n,
      pricePerKB: 50n,
      fileSize: 20480n,
      paymentAddr: targetAddr,
      capsuleHash: new Uint8Array(32),
      expiry: Math.floor(Date.now() / 1000) + 3600,
    }
    const proof: PaymentProof = { rawTx, invoiceID: new Uint8Array(16) }
    expect(() => verifyPayment(proof, inv)).not.toThrow()
  })

  it('throws on nil payment proof', () => {
    const inv: Invoice = {
      id: 'test',
      price: 1000n,
      pricePerKB: 50n,
      fileSize: 20480n,
      paymentAddr: targetAddr,
      capsuleHash: new Uint8Array(32),
      expiry: Math.floor(Date.now() / 1000) + 3600,
    }
    expect(() => verifyPayment(null as unknown as PaymentProof, inv)).toThrow('nil payment proof')
  })

  it('throws on nil invoice', () => {
    const proof: PaymentProof = { rawTx: new Uint8Array([1]), invoiceID: new Uint8Array(16) }
    expect(() => verifyPayment(proof, null as unknown as Invoice)).toThrow('nil invoice')
  })

  it('throws on expired invoice', () => {
    const inv: Invoice = {
      id: 'test',
      price: 1000n,
      pricePerKB: 50n,
      fileSize: 20480n,
      paymentAddr: targetAddr,
      capsuleHash: new Uint8Array(32),
      expiry: Math.floor(Date.now() / 1000) - 1,
    }
    const proof: PaymentProof = { rawTx: new Uint8Array([1]), invoiceID: new Uint8Array(16) }
    expect(() => verifyPayment(proof, inv)).toThrow('invoice expired')
  })

  it('throws on empty raw tx', () => {
    const inv: Invoice = {
      id: 'test',
      price: 1000n,
      pricePerKB: 50n,
      fileSize: 20480n,
      paymentAddr: targetAddr,
      capsuleHash: new Uint8Array(32),
      expiry: Math.floor(Date.now() / 1000) + 3600,
    }
    const proof: PaymentProof = { rawTx: new Uint8Array(0), invoiceID: new Uint8Array(16) }
    expect(() => verifyPayment(proof, inv)).toThrow('empty raw transaction')
  })

  it('throws on insufficient amount', () => {
    const rawTx = buildPaymentTx(targetAddr, 500)
    const inv: Invoice = {
      id: 'test',
      price: 1000n,
      pricePerKB: 50n,
      fileSize: 20480n,
      paymentAddr: targetAddr,
      capsuleHash: new Uint8Array(32),
      expiry: Math.floor(Date.now() / 1000) + 3600,
    }
    const proof: PaymentProof = { rawTx, invoiceID: new Uint8Array(16) }
    expect(() => verifyPayment(proof, inv)).toThrow('insufficient payment')
  })

  it('throws on no matching output (different address)', () => {
    const otherAddr = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'
    const rawTx = buildPaymentTx(otherAddr, 1000)
    const inv: Invoice = {
      id: 'test',
      price: 1000n,
      pricePerKB: 50n,
      fileSize: 20480n,
      paymentAddr: targetAddr,
      capsuleHash: new Uint8Array(32),
      expiry: Math.floor(Date.now() / 1000) + 3600,
    }
    const proof: PaymentProof = { rawTx, invoiceID: new Uint8Array(16) }
    expect(() => verifyPayment(proof, inv)).toThrow('no matching output')
  })

  it('throws on invalid invoice address', () => {
    const rawTx = buildPaymentTx(targetAddr, 1000)
    const inv: Invoice = {
      id: 'test',
      price: 1000n,
      pricePerKB: 50n,
      fileSize: 20480n,
      paymentAddr: 'NOT_A_VALID_ADDRESS!!!',
      capsuleHash: new Uint8Array(32),
      expiry: Math.floor(Date.now() / 1000) + 3600,
    }
    const proof: PaymentProof = { rawTx, invoiceID: new Uint8Array(16) }
    expect(() => verifyPayment(proof, inv)).toThrow('invalid invoice address')
  })
})

// ---------------------------------------------------------------------------
// parseHTLCPreimage tests
// ---------------------------------------------------------------------------

describe('parseHTLCPreimage', () => {
  it('throws on empty spending tx', () => {
    expect(() => parseHTLCPreimage(new Uint8Array(0), null)).toThrow('empty spending transaction')
  })

  it('throws on null spending tx', () => {
    expect(() => parseHTLCPreimage(null as unknown as Uint8Array, null)).toThrow('empty spending transaction')
  })

  it('extracts capsule from valid seller claim tx with 64-byte preimage', () => {
    // Build a mock transaction with claim unlocking script:
    // <sig> <pubkey> <fileTxID||capsule> OP_TRUE
    const tx = new Transaction()

    const fileTxID = new Uint8Array(32)
    fileTxID[0] = 0xf1
    fileTxID[1] = 0xf2

    const capsule = new Uint8Array(32)
    capsule[0] = 0xca
    capsule[1] = 0xfe

    // Preimage = fileTxID (32) || capsule (32) = 64 bytes
    const claimPreimage = new Uint8Array(64)
    claimPreimage.set(fileTxID, 0)
    claimPreimage.set(capsule, 32)

    const dummySig = new Uint8Array(71)
    dummySig[0] = 0x30

    const dummyPub = new Uint8Array(33)
    dummyPub[0] = 0x02

    const unlockScript = new Script()
    unlockScript.writeBin(Array.from(dummySig))
    unlockScript.writeBin(Array.from(dummyPub))
    unlockScript.writeBin(Array.from(claimPreimage))
    unlockScript.writeOpCode(OP.OP_1)   // OP_TRUE for IF branch

    tx.addInput({
      sourceTXID: '0000000000000000000000000000000000000000000000000000000000000001',
      sourceOutputIndex: 0,
      sequence: 0xffffffff,
      unlockingScript: UnlockingScript.fromBinary(unlockScript.toBinary()),
    })

    // Add a dummy output.
    const outScript = new Script()
    outScript.writeOpCode(OP.OP_DUP)
    outScript.writeOpCode(OP.OP_HASH160)
    outScript.writeBin(Array.from(new Uint8Array(20)))
    outScript.writeOpCode(OP.OP_EQUALVERIFY)
    outScript.writeOpCode(OP.OP_CHECKSIG)
    tx.addOutput({
      lockingScript: LockingScript.fromBinary(outScript.toBinary()),
      satoshis: 1000,
    })

    const rawTx = Uint8Array.from(tx.toBinary())
    // parseHTLCPreimage should return just the capsule (32 bytes), not the full 64-byte preimage
    const extracted = parseHTLCPreimage(rawTx, null)
    expect(extracted).toEqual(capsule)
    expect(extracted.length).toBe(32)
  })

  it('rejects preimage shorter than 64 bytes', () => {
    // Build a mock transaction with only a 32-byte preimage (old format)
    const tx = new Transaction()

    const shortPreimage = new Uint8Array(32)
    shortPreimage[0] = 0xca

    const dummySig = new Uint8Array(71)
    dummySig[0] = 0x30

    const dummyPub = new Uint8Array(33)
    dummyPub[0] = 0x02

    const unlockScript = new Script()
    unlockScript.writeBin(Array.from(dummySig))
    unlockScript.writeBin(Array.from(dummyPub))
    unlockScript.writeBin(Array.from(shortPreimage))
    unlockScript.writeOpCode(OP.OP_1)

    tx.addInput({
      sourceTXID: '0000000000000000000000000000000000000000000000000000000000000001',
      sourceOutputIndex: 0,
      sequence: 0xffffffff,
      unlockingScript: UnlockingScript.fromBinary(unlockScript.toBinary()),
    })

    const outScript = new Script()
    outScript.writeOpCode(OP.OP_DUP)
    outScript.writeOpCode(OP.OP_HASH160)
    outScript.writeBin(Array.from(new Uint8Array(20)))
    outScript.writeOpCode(OP.OP_EQUALVERIFY)
    outScript.writeOpCode(OP.OP_CHECKSIG)
    tx.addOutput({
      lockingScript: LockingScript.fromBinary(outScript.toBinary()),
      satoshis: 1000,
    })

    const rawTx = Uint8Array.from(tx.toBinary())
    expect(() => parseHTLCPreimage(rawTx, null)).toThrow('no HTLC preimage found')
  })

  it('verifies fileTxID when provided', () => {
    const tx = new Transaction()

    const fileTxID = new Uint8Array(32)
    fileTxID[0] = 0xf1

    const capsule = new Uint8Array(32)
    capsule[0] = 0xca

    const claimPreimage = new Uint8Array(64)
    claimPreimage.set(fileTxID, 0)
    claimPreimage.set(capsule, 32)

    const dummySig = new Uint8Array(71)
    dummySig[0] = 0x30

    const dummyPub = new Uint8Array(33)
    dummyPub[0] = 0x02

    const unlockScript = new Script()
    unlockScript.writeBin(Array.from(dummySig))
    unlockScript.writeBin(Array.from(dummyPub))
    unlockScript.writeBin(Array.from(claimPreimage))
    unlockScript.writeOpCode(OP.OP_1)

    tx.addInput({
      sourceTXID: '0000000000000000000000000000000000000000000000000000000000000001',
      sourceOutputIndex: 0,
      sequence: 0xffffffff,
      unlockingScript: UnlockingScript.fromBinary(unlockScript.toBinary()),
    })

    const outScript = new Script()
    outScript.writeOpCode(OP.OP_DUP)
    outScript.writeOpCode(OP.OP_HASH160)
    outScript.writeBin(Array.from(new Uint8Array(20)))
    outScript.writeOpCode(OP.OP_EQUALVERIFY)
    outScript.writeOpCode(OP.OP_CHECKSIG)
    tx.addOutput({
      lockingScript: LockingScript.fromBinary(outScript.toBinary()),
      satoshis: 1000,
    })

    const rawTx = Uint8Array.from(tx.toBinary())

    // Correct fileTxID should succeed
    const extracted = parseHTLCPreimage(rawTx, null, fileTxID)
    expect(extracted).toEqual(capsule)

    // Wrong fileTxID should fail
    const wrongFileTxID = new Uint8Array(32)
    wrongFileTxID[0] = 0xff
    expect(() => parseHTLCPreimage(rawTx, null, wrongFileTxID)).toThrow('no HTLC preimage found')
  })

  it('returns error when no HTLC input found (standard P2PKH unlock)', () => {
    // Build a tx with a standard P2PKH unlock (2 chunks, no OP_TRUE at end).
    const tx = new Transaction()
    const dummySig = new Uint8Array(71)
    dummySig[0] = 0x30
    const dummyPub = new Uint8Array(33)
    dummyPub[0] = 0x02

    const unlockScript = new Script()
    unlockScript.writeBin(Array.from(dummySig))
    unlockScript.writeBin(Array.from(dummyPub))

    tx.addInput({
      sourceTXID: '0000000000000000000000000000000000000000000000000000000000000001',
      sourceOutputIndex: 0,
      sequence: 0xffffffff,
      unlockingScript: UnlockingScript.fromBinary(unlockScript.toBinary()),
    })

    const outScript = new Script()
    outScript.writeOpCode(OP.OP_DUP)
    outScript.writeOpCode(OP.OP_HASH160)
    outScript.writeBin(Array.from(new Uint8Array(20)))
    outScript.writeOpCode(OP.OP_EQUALVERIFY)
    outScript.writeOpCode(OP.OP_CHECKSIG)
    tx.addOutput({
      lockingScript: LockingScript.fromBinary(outScript.toBinary()),
      satoshis: 1000,
    })

    const rawTx = Uint8Array.from(tx.toBinary())
    expect(() => parseHTLCPreimage(rawTx, null)).toThrow('no HTLC preimage found')
  })
})

// ---------------------------------------------------------------------------
// Internal test helper: base58 address to PKH bytes
// ---------------------------------------------------------------------------

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function addressToBytes(addr: string): number[] {
  let num = 0n
  for (const char of addr) {
    const idx = BASE58_ALPHABET.indexOf(char)
    if (idx === -1) throw new Error('invalid base58')
    num = num * 58n + BigInt(idx)
  }
  const bytes: number[] = []
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn))
    num >>= 8n
  }
  let leadingZeros = 0
  for (let i = 0; i < addr.length && addr[i] === '1'; i++) leadingZeros++
  const full = [...Array(leadingZeros).fill(0), ...bytes]
  // Address = version(1) + PKH(20) + checksum(4) = 25 bytes
  // Return just the PKH (bytes 1..21).
  return full.slice(1, 21)
}
