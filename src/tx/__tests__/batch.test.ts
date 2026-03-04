import { describe, it, expect } from 'vitest'
import { PrivateKey, PublicKey, Transaction } from '@bsv/sdk'
import {
  MutationBatch,
  BatchOpType,
  DUST_LIMIT,
  TXID_LEN,
  NilParamError,
  InvalidPayloadError,
  InvalidParentTxIDError,
  InsufficientFundsError,
  InvalidParamsError,
  buildP2PKHLockingScript,
  estimateTxSize,
  estimateFee,
  DEFAULT_FEE_RATE,
} from '../index.js'
import type { UTXO, BatchNodeOp } from '../index.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateKeyPair() {
  const priv = PrivateKey.fromRandom()
  const pub = PublicKey.fromPrivateKey(priv)
  return { priv, pub }
}

function filledBytes(len: number, val: number): Uint8Array {
  return new Uint8Array(len).fill(val)
}

function testFeeUTXO(amount: bigint): UTXO {
  return {
    txID: filledBytes(32, 0x01),
    vout: 0,
    amount,
    scriptPubKey: new Uint8Array(25),
  }
}

function testFeeUTXOWithKey(priv: PrivateKey, pub: PublicKey, amount: bigint): UTXO {
  const lockScript = buildP2PKHLockingScript(pub)
  return {
    txID: filledBytes(32, 0x02),
    vout: 0,
    amount,
    scriptPubKey: Uint8Array.from(lockScript.toBinary()),
    privateKey: priv,
  }
}

// ---------------------------------------------------------------------------
// MutationBatch.build()
// ---------------------------------------------------------------------------

describe('MutationBatch.build', () => {
  it('single CreateRoot produces valid TX with 1 OP_RETURN + 1 P2PKH + 1 change', async () => {
    const { pub } = generateKeyPair()

    const batch = new MutationBatch()
    batch.addCreateRoot(pub, new TextEncoder().encode('root-payload'))
    batch.addFeeInput(testFeeUTXO(5000n))
    batch.setChange(filledBytes(20, 0xcc))

    const result = await batch.build()
    expect(result).toBeDefined()
    expect(result.rawTx.length).toBeGreaterThan(0)
    expect(result.nodeOps).toHaveLength(1)
    expect(result.nodeOps[0].opReturnVout).toBe(0)
    expect(result.nodeOps[0].nodeVout).toBe(1)
    expect(result.nodeOps[0].nodeUTXO).toBeDefined()
    expect(result.nodeOps[0].nodeUTXO!.amount).toBe(DUST_LIMIT)
  })

  it('single OpUpdate with existing UTXO', async () => {
    const { priv, pub } = generateKeyPair()
    const parentTxID = filledBytes(32, 0xaa)
    const payload = new TextEncoder().encode('self-update payload data')

    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Update,
      pubKey: pub,
      parentTxID,
      payload,
      inputUTXO: {
        txID: filledBytes(32, 0x11),
        vout: 1,
        amount: DUST_LIMIT,
        scriptPubKey: new Uint8Array(25),
      },
      privateKey: priv,
    })
    batch.addFeeInput(testFeeUTXO(100000n))
    batch.setChange(filledBytes(20, 0xcc))

    const result = await batch.build()
    expect(result).toBeDefined()
    expect(result.nodeOps).toHaveLength(1)
    expect(result.nodeOps[0].opReturnVout).toBe(0)
    expect(result.nodeOps[0].nodeVout).toBe(1)
    expect(result.nodeOps[0].nodeUTXO!.amount).toBe(DUST_LIMIT)
    expect(result.changeUTXO).toBeDefined()
    expect(result.rawTx.length).toBeGreaterThan(0)
  })

  it('parent update + child create produces correct vout mapping', async () => {
    const { priv: parentPriv, pub: parentPub } = generateKeyPair()
    const { pub: childPub } = generateKeyPair()
    const parentTxID = filledBytes(32, 0xaa)

    const batch = new MutationBatch()

    // Op 0: parent update (spending existing P_parent UTXO).
    batch.addNodeOp({
      type: BatchOpType.Update,
      pubKey: parentPub,
      parentTxID: new Uint8Array(0), // root dir
      payload: new TextEncoder().encode('updated parent directory payload'),
      inputUTXO: {
        txID: filledBytes(32, 0x22),
        vout: 1,
        amount: DUST_LIMIT,
        scriptPubKey: new Uint8Array(25),
      },
      privateKey: parentPriv,
    })

    // Op 1: child create (no existing UTXO).
    batch.addNodeOp({
      type: BatchOpType.Create,
      pubKey: childPub,
      parentTxID,
      payload: new TextEncoder().encode('new child node payload'),
    })

    batch.addFeeInput(testFeeUTXO(100000n))
    batch.setChange(filledBytes(20, 0xcc))

    const result = await batch.build()
    expect(result.nodeOps).toHaveLength(2)

    // Op 0: vout 0 (OP_RETURN), vout 1 (P2PKH).
    expect(result.nodeOps[0].opReturnVout).toBe(0)
    expect(result.nodeOps[0].nodeVout).toBe(1)

    // Op 1: vout 2 (OP_RETURN), vout 3 (P2PKH).
    expect(result.nodeOps[1].opReturnVout).toBe(2)
    expect(result.nodeOps[1].nodeVout).toBe(3)

    expect(result.changeUTXO).toBeDefined()
    expect(result.changeUTXO!.vout).toBe(4)
  })

  it('three creates produce sequential vout numbering', async () => {
    const parentTxID = filledBytes(32, 0xcc)

    const batch = new MutationBatch()
    for (let i = 0; i < 3; i++) {
      const { pub } = generateKeyPair()
      batch.addNodeOp({
        type: BatchOpType.Create,
        pubKey: pub,
        parentTxID,
        payload: new TextEncoder().encode('child create payload'),
      })
    }

    batch.addFeeInput(testFeeUTXO(100000n))
    batch.setChange(filledBytes(20, 0xdd))

    const result = await batch.build()
    expect(result.nodeOps).toHaveLength(3)

    for (let i = 0; i < 3; i++) {
      expect(result.nodeOps[i].opReturnVout).toBe(i * 2)
      expect(result.nodeOps[i].nodeVout).toBe(i * 2 + 1)
      expect(result.nodeOps[i].nodeUTXO!.amount).toBe(DUST_LIMIT)
    }

    // Change at vout 6 (3 ops * 2 outputs = 6).
    expect(result.changeUTXO).toBeDefined()
    expect(result.changeUTXO!.vout).toBe(6)
  })

  it('OpDelete produces OP_RETURN but no P2PKH (nodeUTXO is undefined)', async () => {
    const { priv, pub } = generateKeyPair()

    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Delete,
      pubKey: pub,
      parentTxID: filledBytes(32, 0xaa),
      payload: new TextEncoder().encode('delete-payload'),
      inputUTXO: {
        txID: filledBytes(32, 0x03),
        vout: 0,
        amount: 1n,
        scriptPubKey: new Uint8Array(25),
      },
      privateKey: priv,
    })
    batch.addFeeInput(testFeeUTXO(5000n))
    batch.setChange(filledBytes(20, 0xcc))

    const result = await batch.build()
    expect(result.nodeOps).toHaveLength(1)
    expect(result.nodeOps[0].opReturnVout).toBe(0)
    // DELETE: NodeUTXO should be undefined (no P2PKH refresh produced).
    expect(result.nodeOps[0].nodeUTXO).toBeUndefined()
  })

  it('parent UTXO is deduped to one input when shared by two ops', async () => {
    const { pub: childPub } = generateKeyPair()
    const { priv: parentPriv, pub: parentPub } = generateKeyPair()
    const parentTxID = filledBytes(32, 0xbb)

    const parentUTXO: UTXO = {
      txID: filledBytes(32, 0x01),
      vout: 1,
      amount: 1n,
      scriptPubKey: new Uint8Array(25),
    }

    const batch = new MutationBatch()

    // OpCreate for child -- spends parent's UTXO as Metanet edge.
    batch.addNodeOp({
      type: BatchOpType.Create,
      pubKey: childPub,
      parentTxID,
      payload: new TextEncoder().encode('child-payload'),
      inputUTXO: parentUTXO,
      privateKey: parentPriv,
    })

    // OpUpdate for parent -- refreshes the same parent UTXO.
    batch.addNodeOp({
      type: BatchOpType.Update,
      pubKey: parentPub,
      parentTxID: filledBytes(32, 0x00),
      payload: new TextEncoder().encode('parent-updated-children'),
      inputUTXO: parentUTXO, // same UTXO -- should be deduped
      privateKey: parentPriv,
    })

    batch.addFeeInput(testFeeUTXO(5000n))
    batch.setChange(filledBytes(20, 0xee))
    const result = await batch.build()

    // Parse the raw tx to count inputs.
    const sdkTx = Transaction.fromBinary(Array.from(result.rawTx))

    // Should have 2 inputs (1 deduped parent + 1 fee), not 3.
    expect(sdkTx.inputs).toHaveLength(2)

    // Both ops should still produce their outputs.
    expect(result.nodeOps).toHaveLength(2)
    expect(result.nodeOps[0].nodeUTXO).toBeDefined()
    expect(result.nodeOps[1].nodeUTXO).toBeDefined()
  })

  it('fee input overlapping with node input is deduped', async () => {
    const { priv, pub } = generateKeyPair()
    const sharedTxID = filledBytes(32, 0x01)

    const nodeUTXO: UTXO = {
      txID: sharedTxID,
      vout: 1,
      amount: 10000n,
      scriptPubKey: new Uint8Array(25),
    }

    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Update,
      pubKey: pub,
      parentTxID: filledBytes(32, 0xaa),
      payload: new TextEncoder().encode('payload'),
      inputUTXO: nodeUTXO,
      privateKey: priv,
    })
    // Add the same UTXO as a fee input -- should be deduped.
    batch.addFeeInput({
      txID: sharedTxID,
      vout: 1,
      amount: 10000n,
      scriptPubKey: new Uint8Array(25),
    })
    batch.setChange(filledBytes(20, 0xee))

    const result = await batch.build()
    const sdkTx = Transaction.fromBinary(Array.from(result.rawTx))
    expect(sdkTx.inputs).toHaveLength(1)
  })

  it('fee total: outputs + fee <= total inputs', async () => {
    const { pub } = generateKeyPair()

    const batch = new MutationBatch()
    batch.addCreateRoot(pub, new TextEncoder().encode('root-payload'))
    batch.addFeeInput(testFeeUTXO(100000n))
    batch.setChange(filledBytes(20, 0xcc))

    const result = await batch.build()

    // Parse and verify that total outputs + fee <= 100000
    const sdkTx = Transaction.fromBinary(Array.from(result.rawTx))
    let totalOutputSats = 0n
    for (const out of sdkTx.outputs) {
      totalOutputSats += BigInt(out.satoshis ?? 0)
    }
    expect(totalOutputSats).toBeLessThanOrEqual(100000n)
  })
})

// ---------------------------------------------------------------------------
// MutationBatch.build() -- error cases
// ---------------------------------------------------------------------------

describe('MutationBatch.build errors', () => {
  it('no ops throws InvalidPayloadError', async () => {
    const batch = new MutationBatch()
    batch.addFeeInput(testFeeUTXO(100000n))
    await expect(batch.build()).rejects.toThrow(InvalidPayloadError)
  })

  it('no fee inputs throws NilParamError', async () => {
    const { pub } = generateKeyPair()
    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Create,
      pubKey: pub,
      parentTxID: new Uint8Array(0),
      payload: new TextEncoder().encode('test'),
    })
    await expect(batch.build()).rejects.toThrow(NilParamError)
  })

  it('insufficient funds throws InsufficientFundsError', async () => {
    const { pub } = generateKeyPair()
    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Create,
      pubKey: pub,
      parentTxID: new Uint8Array(0),
      payload: new TextEncoder().encode('test payload'),
    })
    batch.addFeeInput(testFeeUTXO(1n)) // way too little
    await expect(batch.build()).rejects.toThrow(InsufficientFundsError)
  })

  it('null PubKey throws NilParamError', async () => {
    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Create,
      pubKey: null as unknown as PublicKey,
      parentTxID: new Uint8Array(0),
      payload: new TextEncoder().encode('test'),
    })
    batch.addFeeInput(testFeeUTXO(100000n))
    await expect(batch.build()).rejects.toThrow(NilParamError)
  })

  it('empty payload throws InvalidPayloadError', async () => {
    const { pub } = generateKeyPair()
    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Create,
      pubKey: pub,
      parentTxID: new Uint8Array(0),
      payload: new Uint8Array(0),
    })
    batch.addFeeInput(testFeeUTXO(100000n))
    await expect(batch.build()).rejects.toThrow(InvalidPayloadError)
  })

  it('invalid parentTxID length throws InvalidParentTxIDError', async () => {
    const { pub } = generateKeyPair()
    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Create,
      pubKey: pub,
      parentTxID: new Uint8Array([0x01, 0x02]), // wrong length
      payload: new TextEncoder().encode('test'),
    })
    batch.addFeeInput(testFeeUTXO(100000n))
    await expect(batch.build()).rejects.toThrow(InvalidParentTxIDError)
  })

  it('inputUTXO without privateKey throws NilParamError', async () => {
    const { pub } = generateKeyPair()
    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Update,
      pubKey: pub,
      parentTxID: new Uint8Array(0),
      payload: new TextEncoder().encode('test'),
      inputUTXO: {
        txID: filledBytes(32, 0x11),
        vout: 0,
        amount: DUST_LIMIT,
        scriptPubKey: new Uint8Array(25),
      },
      privateKey: undefined, // missing
    })
    batch.addFeeInput(testFeeUTXO(100000n))
    await expect(batch.build()).rejects.toThrow(NilParamError)
  })

  it('batch without change address throws InvalidParamsError when change > dust', async () => {
    const { pub: pub1 } = generateKeyPair()

    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Create,
      pubKey: pub1,
      parentTxID: new Uint8Array(0),
      payload: new TextEncoder().encode('payload1'),
    })
    batch.addFeeInput(testFeeUTXO(100000n))
    await expect(batch.build()).rejects.toThrow(InvalidParamsError)
  })

  it('change below dust is suppressed', async () => {
    const { pub } = generateKeyPair()
    const payload = new TextEncoder().encode('test payload data')

    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Create,
      pubKey: pub,
      parentTxID: new Uint8Array(0),
      payload,
    })

    // Calculate exact amount that leaves change <= dust.
    const numOutputs = 3
    const estSize = estimateTxSize(1, numOutputs, payload.length)
    const estFee = estimateFee(estSize, DEFAULT_FEE_RATE)
    const feeAmount = DUST_LIMIT + estFee + 1n // change = 1 sat <= dust

    batch.addFeeInput(testFeeUTXO(feeAmount))
    batch.setChange(filledBytes(20, 0xcc))

    const result = await batch.build()
    expect(result.changeUTXO).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// MutationBatch convenience builders
// ---------------------------------------------------------------------------

describe('MutationBatch convenience builders', () => {
  it('addCreateChild sets opCount to 1', () => {
    const { priv, pub } = generateKeyPair()
    const { pub: childPub } = generateKeyPair()

    const batch = new MutationBatch()
    batch.addCreateChild(
      childPub,
      filledBytes(32, 0xaa),
      new TextEncoder().encode('payload'),
      {
        txID: filledBytes(32, 0x01),
        vout: 1,
        amount: 1n,
        scriptPubKey: new Uint8Array(25),
      },
      priv,
    )
    expect(batch.opCount()).toBe(1)
  })

  it('addSelfUpdate sets opCount to 1', () => {
    const { priv, pub } = generateKeyPair()

    const batch = new MutationBatch()
    batch.addSelfUpdate(
      pub,
      filledBytes(32, 0xaa),
      new TextEncoder().encode('payload'),
      {
        txID: filledBytes(32, 0x01),
        vout: 1,
        amount: 1n,
        scriptPubKey: new Uint8Array(25),
      },
      priv,
    )
    expect(batch.opCount()).toBe(1)
  })

  it('addDelete sets opCount to 1', () => {
    const { priv, pub } = generateKeyPair()

    const batch = new MutationBatch()
    batch.addDelete(
      pub,
      filledBytes(32, 0xaa),
      new TextEncoder().encode('payload'),
      {
        txID: filledBytes(32, 0x01),
        vout: 1,
        amount: 1n,
        scriptPubKey: new Uint8Array(25),
      },
      priv,
    )
    expect(batch.opCount()).toBe(1)
  })

  it('addCreateRoot sets opCount to 1', () => {
    const { pub } = generateKeyPair()

    const batch = new MutationBatch()
    batch.addCreateRoot(pub, new TextEncoder().encode('payload'))
    expect(batch.opCount()).toBe(1)
  })

  it('addCreateRoot builds successfully', async () => {
    const { pub } = generateKeyPair()

    const batch = new MutationBatch()
    batch.addCreateRoot(pub, new TextEncoder().encode('root-payload'))
    batch.addFeeInput(testFeeUTXO(5000n))
    batch.setChange(filledBytes(20, 0xcc))

    const result = await batch.build()
    expect(result.nodeOps).toHaveLength(1)
    expect(result.nodeOps[0].nodeUTXO).toBeDefined()
  })
})

// ---------------------------------------------------------------------------
// MutationBatch.sign()
// ---------------------------------------------------------------------------

describe('MutationBatch.sign', () => {
  it('signs a single-op CreateRoot and populates TxID', async () => {
    const { priv, pub } = generateKeyPair()

    const feeUTXO = testFeeUTXOWithKey(priv, pub, 100000n)

    const batch = new MutationBatch()
    batch.addCreateRoot(pub, new TextEncoder().encode('test metanet root payload'))
    batch.addFeeInput(feeUTXO)
    batch.setChange(filledBytes(20, 0xcc))

    const result = await batch.build()
    expect(result.rawTx.length).toBeGreaterThan(0)

    const signedHex = await batch.sign(result)
    expect(signedHex).toBeTruthy()
    expect(signedHex.length).toBeGreaterThan(0)

    // TxID should be set on result.
    expect(result.txID).toBeDefined()
    expect(result.txID.length).toBe(TXID_LEN)

    // NodeUTXO should have TxID.
    expect(result.nodeOps[0].nodeUTXO!.txID).toEqual(result.txID)

    // The signed hex should be parseable.
    const parsedTx = Transaction.fromHex(signedHex)
    expect(parsedTx.inputs).toHaveLength(1)
    expect(parsedTx.inputs[0].unlockingScript).toBeTruthy()
  })

  it('signs a single-op OpUpdate with node input + fee input', async () => {
    const { priv, pub } = generateKeyPair()

    const nodeScript = buildP2PKHLockingScript(pub)
    const nodeScriptBytes = Uint8Array.from(nodeScript.toBinary())

    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Update,
      pubKey: pub,
      parentTxID: filledBytes(32, 0xcc),
      payload: new TextEncoder().encode('update-payload'),
      inputUTXO: {
        txID: filledBytes(32, 0x01),
        vout: 0,
        amount: 1n,
        scriptPubKey: nodeScriptBytes,
        privateKey: priv,
      },
      privateKey: priv,
    })
    batch.addFeeInput({
      txID: filledBytes(32, 0x02),
      vout: 0,
      amount: 5000n,
      scriptPubKey: nodeScriptBytes,
      privateKey: priv,
    })
    batch.setChange(filledBytes(20, 0xcc))

    const result = await batch.build()
    const txHex = await batch.sign(result)
    expect(txHex).toBeTruthy()

    // TxID should be set on result and all NodeUTXOs.
    expect(result.txID).toBeDefined()
    expect(result.nodeOps[0].nodeUTXO!.txID).toEqual(result.txID)
  })

  it('signs multi-op batch with deduped parent UTXO', async () => {
    const { pub: childPub } = generateKeyPair()
    const { priv: parentPriv, pub: parentPub } = generateKeyPair()
    const { priv: feePriv, pub: feePub } = generateKeyPair()

    const parentScript = buildP2PKHLockingScript(parentPub)
    const parentScriptBytes = Uint8Array.from(parentScript.toBinary())
    const feeScript = buildP2PKHLockingScript(feePub)
    const feeScriptBytes = Uint8Array.from(feeScript.toBinary())

    const parentUTXO: UTXO = {
      txID: filledBytes(32, 0x01),
      vout: 1,
      amount: 1n,
      scriptPubKey: parentScriptBytes,
      privateKey: parentPriv,
    }

    const batch = new MutationBatch()
    batch.addNodeOp({
      type: BatchOpType.Create,
      pubKey: childPub,
      parentTxID: filledBytes(32, 0xbb),
      payload: new TextEncoder().encode('child-payload'),
      inputUTXO: parentUTXO,
      privateKey: parentPriv,
    })
    batch.addNodeOp({
      type: BatchOpType.Update,
      pubKey: parentPub,
      parentTxID: filledBytes(32, 0x00),
      payload: new TextEncoder().encode('parent-updated'),
      inputUTXO: parentUTXO, // same UTXO
      privateKey: parentPriv,
    })
    batch.addFeeInput({
      txID: filledBytes(32, 0x02),
      vout: 0,
      amount: 5000n,
      scriptPubKey: feeScriptBytes,
      privateKey: feePriv,
    })
    batch.setChange(filledBytes(20, 0xff))

    const result = await batch.build()
    const txHex = await batch.sign(result)
    expect(txHex).toBeTruthy()

    // Both NodeUTXOs should have TxID set.
    expect(result.nodeOps[0].nodeUTXO!.txID).toEqual(result.txID)
    expect(result.nodeOps[1].nodeUTXO!.txID).toEqual(result.txID)
    if (result.changeUTXO) {
      expect(result.changeUTXO.txID).toEqual(result.txID)
    }
  })
})
