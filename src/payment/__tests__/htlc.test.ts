import { describe, it, expect } from 'vitest'
import { Hash, OP, Script, Transaction, PrivateKey, UnlockingScript, LockingScript } from '@bsv/sdk'
import {
  buildHTLC,
  extractCapsuleHashFromHTLC,
  extractInvoiceIDFromHTLC,
} from '../htlc.js'
import { verifyPayment, parseHTLCPreimage } from '../verify.js'
import {
  loadArtifact,
  instantiateHTLC,
  isArtifactScript,
  encodeScryptInt,
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
// loadArtifact tests
// ---------------------------------------------------------------------------

describe('loadArtifact', () => {
  it('returns the embedded artifact with correct structure', () => {
    const art = loadArtifact()
    expect(art.hex).toBeTruthy()
    expect(art.abi.length).toBe(3)
    expect(art.contract).toBe('BitfsHTLC')
    expect(art.version).toBe(9)

    // Verify ABI has constructor + 2 methods
    const hasConstructor = art.abi.some(a => a.type === 'constructor')
    const hasClaim = art.abi.some(a => a.type === 'function' && a.name === 'claim')
    const hasRefund = art.abi.some(a => a.type === 'function' && a.name === 'refund')
    expect(hasConstructor).toBe(true)
    expect(hasClaim).toBe(true)
    expect(hasRefund).toBe(true)
  })

  it('hex template contains all 5 placeholders', () => {
    const art = loadArtifact()
    expect(art.hex).toContain('<invoiceId>')
    expect(art.hex).toContain('<capsuleHash>')
    expect(art.hex).toContain('<sellerPkh>')
    expect(art.hex).toContain('<buyerPkh>')
    expect(art.hex).toContain('<timeout>')
  })
})

// ---------------------------------------------------------------------------
// instantiateHTLC tests
// ---------------------------------------------------------------------------

describe('instantiateHTLC', () => {
  it('produces a non-empty script with no placeholders', () => {
    const invoiceId = new Uint8Array(INVOICE_ID_LEN)
    const capsuleHash = new Uint8Array(CAPSULE_HASH_LEN)
    const sellerPkh = new Uint8Array(PUB_KEY_HASH_LEN)
    const buyerPkh = new Uint8Array(PUB_KEY_HASH_LEN)
    const script = instantiateHTLC(invoiceId, capsuleHash, sellerPkh, buyerPkh, 72)
    expect(script.length).toBeGreaterThan(0)

    const hexStr = toHex(script)
    expect(hexStr).not.toContain('<')
    expect(hexStr).not.toContain('>')
  })

  it('embeds parameters at correct byte offsets', () => {
    const invoiceId = new Uint8Array(INVOICE_ID_LEN)
    for (let i = 0; i < INVOICE_ID_LEN; i++) invoiceId[i] = i + 1
    const capsuleHash = new Uint8Array(CAPSULE_HASH_LEN).fill(0xaa)
    const sellerPkh = new Uint8Array(PUB_KEY_HASH_LEN).fill(0xbb)
    const buyerPkh = new Uint8Array(PUB_KEY_HASH_LEN).fill(0xcc)

    const script = instantiateHTLC(invoiceId, capsuleHash, sellerPkh, buyerPkh, 144)
    const hexStr = toHex(script)

    // Verify the substituted values appear
    expect(hexStr).toContain(toHex(invoiceId))
    expect(hexStr).toContain(toHex(capsuleHash))
    expect(hexStr).toContain(toHex(sellerPkh))
    expect(hexStr).toContain(toHex(buyerPkh))
    // timeout=144 in sCrypt int encoding: 9000
    expect(hexStr).toContain('9000')
  })

  it('is deterministic', () => {
    const invoiceId = new Uint8Array(INVOICE_ID_LEN)
    const capsuleHash = new Uint8Array(CAPSULE_HASH_LEN)
    const sellerPkh = new Uint8Array(PUB_KEY_HASH_LEN)
    const buyerPkh = new Uint8Array(PUB_KEY_HASH_LEN)

    const script1 = instantiateHTLC(invoiceId, capsuleHash, sellerPkh, buyerPkh, 72)
    const script2 = instantiateHTLC(invoiceId, capsuleHash, sellerPkh, buyerPkh, 72)
    expect(script1).toEqual(script2)
  })

  it('throws on wrong invoiceId length', () => {
    expect(() =>
      instantiateHTLC(
        new Uint8Array(10),
        new Uint8Array(CAPSULE_HASH_LEN),
        new Uint8Array(PUB_KEY_HASH_LEN),
        new Uint8Array(PUB_KEY_HASH_LEN),
        72,
      ),
    ).toThrow('invoiceId')
  })

  it('throws on wrong capsuleHash length', () => {
    expect(() =>
      instantiateHTLC(
        new Uint8Array(INVOICE_ID_LEN),
        new Uint8Array(16),
        new Uint8Array(PUB_KEY_HASH_LEN),
        new Uint8Array(PUB_KEY_HASH_LEN),
        72,
      ),
    ).toThrow('capsuleHash')
  })

  it('throws on wrong sellerPkh length', () => {
    expect(() =>
      instantiateHTLC(
        new Uint8Array(INVOICE_ID_LEN),
        new Uint8Array(CAPSULE_HASH_LEN),
        new Uint8Array(10),
        new Uint8Array(PUB_KEY_HASH_LEN),
        72,
      ),
    ).toThrow('sellerPkh')
  })

  it('throws on wrong buyerPkh length', () => {
    expect(() =>
      instantiateHTLC(
        new Uint8Array(INVOICE_ID_LEN),
        new Uint8Array(CAPSULE_HASH_LEN),
        new Uint8Array(PUB_KEY_HASH_LEN),
        new Uint8Array(10),
        72,
      ),
    ).toThrow('buyerPkh')
  })
})

// ---------------------------------------------------------------------------
// encodeScryptInt tests
// ---------------------------------------------------------------------------

describe('encodeScryptInt', () => {
  it.each([
    [0, '00'],
    [1, '01'],
    [72, '48'],
    [127, '7f'],
    [128, '8000'],
    [144, '9000'],
    [255, 'ff00'],
    [256, '0001'],
    [288, '2001'],
    [-1, '81'],
    [-128, '8080'],
  ])('encodes %d as %s', (value, expected) => {
    expect(encodeScryptInt(value)).toBe(expected)
  })
})

// ---------------------------------------------------------------------------
// isArtifactScript tests
// ---------------------------------------------------------------------------

describe('isArtifactScript', () => {
  it('identifies artifact scripts', () => {
    const params = validHTLCParams()
    const script = buildHTLC(params)
    expect(isArtifactScript(script)).toBe(true)
  })

  it('rejects non-artifact scripts', () => {
    expect(isArtifactScript(new Uint8Array([0x63, 0xa8]))).toBe(false)
  })

  it('rejects empty scripts', () => {
    expect(isArtifactScript(new Uint8Array(0))).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// buildHTLC tests
// ---------------------------------------------------------------------------

describe('buildHTLC', () => {
  it('produces a valid sCrypt artifact script', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)
    expect(scriptBytes.length).toBeGreaterThan(HTLC_MIN_SCRIPT_LEN)

    // Should be identified as an artifact script
    expect(isArtifactScript(scriptBytes)).toBe(true)

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

  it('embeds buyer PKH (derived from pubkey) at correct byte offset', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)

    const buyerPkh = Uint8Array.from(Hash.hash160(Array.from(params.buyerPubKey)))
    const embedded = scriptBytes.slice(
      HTLC_BUYER_PKH_OFFSET,
      HTLC_BUYER_PKH_OFFSET + PUB_KEY_HASH_LEN,
    )
    expect(embedded).toEqual(buyerPkh)
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
  it('extracts capsule hash from artifact script', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)
    const extracted = extractCapsuleHashFromHTLC(scriptBytes)
    expect(extracted).toEqual(params.capsuleHash)
  })

  it('throws on script too short', () => {
    expect(() => extractCapsuleHashFromHTLC(new Uint8Array(10))).toThrow('too short')
  })

  it('throws on non-artifact script', () => {
    // Create a large enough but non-matching script
    const fake = new Uint8Array(HTLC_MIN_SCRIPT_LEN + 10).fill(0x63)
    expect(() => extractCapsuleHashFromHTLC(fake)).toThrow('does not match')
  })
})

// ---------------------------------------------------------------------------
// extractInvoiceIDFromHTLC tests
// ---------------------------------------------------------------------------

describe('extractInvoiceIDFromHTLC', () => {
  it('extracts invoice ID from artifact script', () => {
    const params = validHTLCParams()
    const scriptBytes = buildHTLC(params)
    const extracted = extractInvoiceIDFromHTLC(scriptBytes)

    expect(extracted).not.toBeNull()
    expect(extracted).toEqual(params.invoiceID)
  })

  it('returns null for empty script', () => {
    expect(extractInvoiceIDFromHTLC(new Uint8Array(0))).toBeNull()
  })

  it('returns null for non-artifact script', () => {
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

  it('extracts preimage from valid sCrypt seller claim tx', () => {
    // Build a mock transaction with sCrypt claim unlocking script:
    // <capsule> <sig> <pubkey> OP_0
    const tx = new Transaction()

    const preimage = new Uint8Array(32)
    preimage[0] = 0xca
    preimage[1] = 0xfe

    const dummySig = new Uint8Array(71)
    dummySig[0] = 0x30

    const dummyPub = new Uint8Array(33)
    dummyPub[0] = 0x02

    const unlockScript = new Script()
    unlockScript.writeBin(Array.from(preimage))
    unlockScript.writeBin(Array.from(dummySig))
    unlockScript.writeBin(Array.from(dummyPub))
    unlockScript.writeOpCode(OP.OP_0)

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
    // Build a tx with a standard P2PKH unlock (2 chunks, no OP_0 at end).
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
