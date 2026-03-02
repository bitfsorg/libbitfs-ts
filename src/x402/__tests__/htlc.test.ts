import { describe, it, expect } from 'vitest'
import { Hash, OP, Script, Transaction, PrivateKey, UnlockingScript, LockingScript } from '@bsv/sdk'
import {
  buildHTLC,
  extractCapsuleHashFromHTLC,
  extractInvoiceIDFromHTLC,
} from '../htlc.js'
import { verifyPayment, parseHTLCPreimage } from '../verify.js'
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

function validHTLCParams(): HTLCParams {
  return {
    buyerPubKey: makeBuyerPubKey(),
    sellerPubKey: makeSellerPubKey(),
    sellerPubKeyHash: makeSellerPKH(),
    capsuleHash: makeCapsuleHash(),
    amount: 1000n,
    timeoutBlocks: DEFAULT_HTLC_TIMEOUT,
  }
}

// ---------------------------------------------------------------------------
// buildHTLC tests
// ---------------------------------------------------------------------------

describe('buildHTLC', () => {
  it('produces a valid script (legacy format without invoice ID)', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)
    expect(scriptBytes.length).toBeGreaterThan(0)

    // Parse and verify structure.
    const s = Script.fromBinary(Array.from(scriptBytes))
    const chunks = s.chunks

    // First chunk: OP_IF
    expect(chunks[0].op).toBe(OP.OP_IF)

    // Second chunk: OP_SHA256
    expect(chunks[1].op).toBe(OP.OP_SHA256)

    // Third chunk: capsule hash data (32 bytes)
    expect(chunks[2].data).toBeDefined()
    expect(chunks[2].data!.length).toBe(CAPSULE_HASH_LEN)
    expect(Uint8Array.from(chunks[2].data!)).toEqual(params.capsuleHash)

    // Fourth chunk: OP_EQUALVERIFY
    expect(chunks[3].op).toBe(OP.OP_EQUALVERIFY)

    // Find OP_ELSE
    const hasElse = chunks.some(c => c.op === OP.OP_ELSE)
    expect(hasElse).toBe(true)

    // Find OP_CHECKMULTISIG (buyer refund path)
    const hasMultisig = chunks.some(c => c.op === OP.OP_CHECKMULTISIG)
    expect(hasMultisig).toBe(true)

    // Last chunk: OP_ENDIF
    expect(chunks[chunks.length - 1].op).toBe(OP.OP_ENDIF)
  })

  it('contains buyer pubkey in refund path', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)
    const s = Script.fromBinary(Array.from(scriptBytes))

    const found = s.chunks.some(
      c => c.data != null && c.data.length === COMPRESSED_PUB_KEY_LEN &&
        Uint8Array.from(c.data).every((b, i) => b === params.buyerPubKey[i]),
    )
    expect(found).toBe(true)
  })

  it('contains seller pubkey in refund path', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)
    const s = Script.fromBinary(Array.from(scriptBytes))

    const found = s.chunks.some(
      c => c.data != null && c.data.length === COMPRESSED_PUB_KEY_LEN &&
        Uint8Array.from(c.data).every((b, i) => b === params.sellerPubKey[i]),
    )
    expect(found).toBe(true)
  })

  it('contains seller address hash in claim path', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)
    const s = Script.fromBinary(Array.from(scriptBytes))

    const found = s.chunks.some(
      c => c.data != null && c.data.length === PUB_KEY_HASH_LEN &&
        Uint8Array.from(c.data).every((b, i) => b === params.sellerPubKeyHash[i]),
    )
    expect(found).toBe(true)
  })

  it('includes invoice ID prefix when provided', () => {
    const params = validHTLCParams()
    const invoiceID = new Uint8Array(INVOICE_ID_LEN)
    for (let i = 0; i < INVOICE_ID_LEN; i++) invoiceID[i] = i + 200
    params.invoiceID = invoiceID

    const scriptBytes = buildHTLC(params)
    const s = Script.fromBinary(Array.from(scriptBytes))
    const chunks = s.chunks

    // First chunk: invoice ID data
    expect(chunks[0].data).toBeDefined()
    expect(chunks[0].data!.length).toBe(INVOICE_ID_LEN)
    expect(Uint8Array.from(chunks[0].data!)).toEqual(invoiceID)

    // Second chunk: OP_DROP
    expect(chunks[1].op).toBe(OP.OP_DROP)

    // Third chunk: OP_IF (standard HTLC body)
    expect(chunks[2].op).toBe(OP.OP_IF)
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

  it('throws on invalid seller pubkey length', () => {
    const params = validHTLCParams()
    params.sellerPubKey = new Uint8Array([0x03, 0x01])
    expect(() => buildHTLC(params)).toThrow('seller pubkey must be 33 bytes')
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
    expect(() => buildHTLC(params)).toThrow('invoice ID must be 16 bytes')
  })

  it('accepts empty invoiceID (no prefix)', () => {
    const params = validHTLCParams()
    params.invoiceID = new Uint8Array(0)
    const scriptBytes = buildHTLC(params)
    const s = Script.fromBinary(Array.from(scriptBytes))
    expect(s.chunks[0].op).toBe(OP.OP_IF)
  })
})

// ---------------------------------------------------------------------------
// extractCapsuleHashFromHTLC tests
// ---------------------------------------------------------------------------

describe('extractCapsuleHashFromHTLC', () => {
  it('extracts capsule hash from legacy format', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)
    const extracted = extractCapsuleHashFromHTLC(scriptBytes)
    expect(extracted).toEqual(params.capsuleHash)
  })

  it('extracts capsule hash from format with invoice ID', () => {
    const params = validHTLCParams()
    params.invoiceID = new Uint8Array(INVOICE_ID_LEN).fill(0xaa)
    const scriptBytes = buildHTLC(params)
    const extracted = extractCapsuleHashFromHTLC(scriptBytes)
    expect(extracted).toEqual(params.capsuleHash)
  })

  it('throws on script too short', () => {
    expect(() => extractCapsuleHashFromHTLC(new Uint8Array([OP.OP_IF]))).toThrow('too short')
  })
})

// ---------------------------------------------------------------------------
// extractInvoiceIDFromHTLC tests
// ---------------------------------------------------------------------------

describe('extractInvoiceIDFromHTLC', () => {
  it('returns null for legacy format (no invoice ID)', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)
    const result = extractInvoiceIDFromHTLC(scriptBytes)
    expect(result).toBeNull()
  })

  it('extracts invoice ID when present', () => {
    const params = validHTLCParams()
    const invoiceID = new Uint8Array(INVOICE_ID_LEN)
    for (let i = 0; i < INVOICE_ID_LEN; i++) invoiceID[i] = i + 200
    params.invoiceID = invoiceID

    const scriptBytes = buildHTLC(params)
    const extracted = extractInvoiceIDFromHTLC(scriptBytes)

    expect(extracted).not.toBeNull()
    expect(extracted).toEqual(invoiceID)
  })

  it('returns null for empty script', () => {
    expect(extractInvoiceIDFromHTLC(new Uint8Array(0))).toBeNull()
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

  it('extracts preimage from valid seller claim tx', () => {
    // Build a mock transaction with seller-claim unlocking script:
    // <sig> <pubkey> <preimage> OP_TRUE
    const tx = new Transaction()

    const preimage = new Uint8Array(32)
    preimage[0] = 0xca
    preimage[1] = 0xfe

    const dummySig = new Uint8Array(71)
    dummySig[0] = 0x30

    const dummyPub = new Uint8Array(33)
    dummyPub[0] = 0x02

    const unlockScript = new Script()
    unlockScript.writeBin(Array.from(dummySig))
    unlockScript.writeBin(Array.from(dummyPub))
    unlockScript.writeBin(Array.from(preimage))
    unlockScript.writeOpCode(OP.OP_TRUE)

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
    const extracted = parseHTLCPreimage(rawTx, null)
    expect(extracted).toEqual(preimage)
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

    const { UnlockingScript, LockingScript } = require('@bsv/sdk')

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
