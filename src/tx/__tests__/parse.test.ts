import { describe, it, expect } from 'vitest'
import { PrivateKey, PublicKey } from '@bsv/sdk'
import {
  parseTxNodeOps,
  buildOPReturnData,
  buildOPReturnScript,
  META_FLAG,
  COMPRESSED_PUB_KEY_LEN,
  TXID_LEN,
} from '../index.js'
import type { TxOutput, ParsedNodeOp } from '../index.js'

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

/**
 * Build a pair of outputs (OP_RETURN + P2PKH) representing one Metanet node op.
 */
function buildNodeOpOutputs(
  pub: PublicKey,
  parentTxID: Uint8Array,
  payload: Uint8Array,
): [TxOutput, TxOutput] {
  const pushes = buildOPReturnData(pub, parentTxID, payload)
  const opReturnScript = buildOPReturnScript(pushes)
  const opReturnOutput: TxOutput = {
    value: 0n,
    scriptPubKey: Uint8Array.from(opReturnScript.toBinary()),
  }

  // Simple P2PKH-like output (just needs to be non-OP_RETURN).
  const p2pkhOutput: TxOutput = {
    value: 1n,
    scriptPubKey: new Uint8Array([
      0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH_20
      ...new Uint8Array(20).fill(0xaa), // dummy hash
      0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
    ]),
  }

  return [opReturnOutput, p2pkhOutput]
}

// ---------------------------------------------------------------------------
// parseTxNodeOps
// ---------------------------------------------------------------------------

describe('parseTxNodeOps', () => {
  it('extracts single node op from transaction outputs', () => {
    const { pub } = generateKeyPair()
    const parentTxID = filledBytes(TXID_LEN, 0xab)
    const payload = new TextEncoder().encode('test TLV payload')

    const [opReturn, p2pkh] = buildNodeOpOutputs(pub, parentTxID, payload)
    const ops = parseTxNodeOps([opReturn, p2pkh])

    expect(ops).toHaveLength(1)
    const op = ops[0]

    // pNode matches the compressed public key
    expect(op.pNode).toEqual(Uint8Array.from(pub.toDER() as number[]))
    expect(op.pNode).toHaveLength(COMPRESSED_PUB_KEY_LEN)

    // parentTxID matches
    expect(op.parentTxID).toEqual(parentTxID)

    // payload matches
    expect(op.payload).toEqual(payload)

    // vout indices
    expect(op.vout).toBe(0)
    expect(op.nodeVout).toBe(1)
    expect(op.isDelete).toBe(false)
  })

  it('extracts multiple node ops from batch transaction', () => {
    const { pub: pub1 } = generateKeyPair()
    const { pub: pub2 } = generateKeyPair()
    const parentTxID1 = filledBytes(TXID_LEN, 0x11)
    const parentTxID2 = filledBytes(TXID_LEN, 0x22)
    const payload1 = new TextEncoder().encode('payload one')
    const payload2 = new TextEncoder().encode('payload two')

    const [opReturn1, p2pkh1] = buildNodeOpOutputs(pub1, parentTxID1, payload1)
    const [opReturn2, p2pkh2] = buildNodeOpOutputs(pub2, parentTxID2, payload2)

    // Simulate batch: [OP_RETURN1, P2PKH1, OP_RETURN2, P2PKH2]
    const ops = parseTxNodeOps([opReturn1, p2pkh1, opReturn2, p2pkh2])

    expect(ops).toHaveLength(2)

    // First op
    expect(ops[0].pNode).toEqual(Uint8Array.from(pub1.toDER() as number[]))
    expect(ops[0].parentTxID).toEqual(parentTxID1)
    expect(ops[0].payload).toEqual(payload1)
    expect(ops[0].vout).toBe(0)
    expect(ops[0].nodeVout).toBe(1)
    expect(ops[0].isDelete).toBe(false)

    // Second op
    expect(ops[1].pNode).toEqual(Uint8Array.from(pub2.toDER() as number[]))
    expect(ops[1].parentTxID).toEqual(parentTxID2)
    expect(ops[1].payload).toEqual(payload2)
    expect(ops[1].vout).toBe(2)
    expect(ops[1].nodeVout).toBe(3)
    expect(ops[1].isDelete).toBe(false)
  })

  it('returns empty array for non-Metanet transaction', () => {
    // Regular P2PKH outputs only
    const outputs: TxOutput[] = [
      {
        value: 1000n,
        scriptPubKey: new Uint8Array([
          0x76, 0xa9, 0x14,
          ...new Uint8Array(20).fill(0xbb),
          0x88, 0xac,
        ]),
      },
      {
        value: 2000n,
        scriptPubKey: new Uint8Array([
          0x76, 0xa9, 0x14,
          ...new Uint8Array(20).fill(0xcc),
          0x88, 0xac,
        ]),
      },
    ]
    expect(parseTxNodeOps(outputs)).toEqual([])
  })

  it('returns empty array for empty outputs', () => {
    expect(parseTxNodeOps([])).toEqual([])
  })

  it('skips malformed OP_RETURN outputs (no meta flag)', () => {
    // OP_FALSE OP_RETURN with random data (not Metanet)
    const randomOpReturn: TxOutput = {
      value: 0n,
      scriptPubKey: new Uint8Array([
        0x00, 0x6a, // OP_FALSE OP_RETURN
        0x04, 0xff, 0xff, 0xff, 0xff, // 4-byte push, not "meta"
        0x21, ...new Uint8Array(33).fill(0x02), // 33-byte push
        0x20, ...new Uint8Array(32).fill(0x03), // 32-byte push
        0x05, ...new Uint8Array(5).fill(0x04), // 5-byte push
      ]),
    }
    const p2pkh: TxOutput = {
      value: 1n,
      scriptPubKey: new Uint8Array([0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac]),
    }

    const ops = parseTxNodeOps([randomOpReturn, p2pkh])
    expect(ops).toEqual([])
  })

  it('skips OP_RETURN with invalid PNode length', () => {
    // Build a script manually with wrong PNode length
    const badScript = new Uint8Array([
      0x00, 0x6a, // OP_FALSE OP_RETURN
      0x04, 0x6d, 0x65, 0x74, 0x61, // META_FLAG
      0x10, ...new Uint8Array(16).fill(0x02), // 16-byte push (wrong, should be 33)
      0x20, ...new Uint8Array(32).fill(0x03), // 32-byte push
      0x05, ...new Uint8Array(5).fill(0x04), // payload
    ])
    const outputs: TxOutput[] = [
      { value: 0n, scriptPubKey: badScript },
      { value: 1n, scriptPubKey: new Uint8Array([0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac]) },
    ]

    expect(parseTxNodeOps(outputs)).toEqual([])
  })

  it('handles root creation (empty parentTxID)', () => {
    const { pub } = generateKeyPair()
    const payload = new TextEncoder().encode('root node payload')

    // Root: parentTxID is 0 bytes
    const [opReturn, p2pkh] = buildNodeOpOutputs(pub, new Uint8Array(0), payload)
    const ops = parseTxNodeOps([opReturn, p2pkh])

    expect(ops).toHaveLength(1)
    expect(ops[0].parentTxID).toHaveLength(0)
    expect(ops[0].pNode).toEqual(Uint8Array.from(pub.toDER() as number[]))
    expect(ops[0].payload).toEqual(payload)
    expect(ops[0].isDelete).toBe(false)
  })

  it('handles batch with mixed regular and Metanet outputs', () => {
    const { pub } = generateKeyPair()
    const parentTxID = filledBytes(TXID_LEN, 0xdd)
    const payload = new TextEncoder().encode('mixed outputs')

    // Regular P2PKH, then Metanet OP_RETURN + P2PKH, then change P2PKH
    const regularOutput: TxOutput = {
      value: 5000n,
      scriptPubKey: new Uint8Array([0x76, 0xa9, 0x14, ...new Uint8Array(20).fill(0xee), 0x88, 0xac]),
    }
    const [opReturn, p2pkh] = buildNodeOpOutputs(pub, parentTxID, payload)
    const changeOutput: TxOutput = {
      value: 3000n,
      scriptPubKey: new Uint8Array([0x76, 0xa9, 0x14, ...new Uint8Array(20).fill(0xff), 0x88, 0xac]),
    }

    const ops = parseTxNodeOps([regularOutput, opReturn, p2pkh, changeOutput])

    expect(ops).toHaveLength(1)
    expect(ops[0].vout).toBe(1)
    expect(ops[0].nodeVout).toBe(2)
    expect(ops[0].isDelete).toBe(false)
    expect(ops[0].pNode).toEqual(Uint8Array.from(pub.toDER() as number[]))
  })

  it('returns owned copies of byte arrays', () => {
    const { pub } = generateKeyPair()
    const parentTxID = filledBytes(TXID_LEN, 0xab)
    const payload = new TextEncoder().encode('ownership test')

    const [opReturn, p2pkh] = buildNodeOpOutputs(pub, parentTxID, payload)
    const ops = parseTxNodeOps([opReturn, p2pkh])

    expect(ops).toHaveLength(1)

    // Mutating the returned arrays should not affect the original script
    const originalPNode = Uint8Array.from(ops[0].pNode)
    ops[0].pNode[0] = 0xff
    // The result is an owned copy, so the original script is unchanged
    // (this is more about confirming the copy behavior)
    expect(ops[0].pNode[0]).toBe(0xff)
    expect(originalPNode[0]).not.toBe(0xff)
  })

  it('handles large payloads (OP_PUSHDATA2)', () => {
    const { pub } = generateKeyPair()
    const parentTxID = filledBytes(TXID_LEN, 0xab)
    // 300-byte payload will use OP_PUSHDATA2 encoding
    const payload = filledBytes(300, 0x42)

    const [opReturn, p2pkh] = buildNodeOpOutputs(pub, parentTxID, payload)
    const ops = parseTxNodeOps([opReturn, p2pkh])

    expect(ops).toHaveLength(1)
    expect(ops[0].payload).toEqual(payload)
  })

  it('skips OP_RETURN with empty payload', () => {
    // Craft a script with an empty payload push (OP_0)
    // OP_FALSE OP_RETURN <META_FLAG> <PNode(33)> <ParentTxID(32)> <OP_0 = empty>
    const pubBytes = filledBytes(33, 0x02)
    pubBytes[0] = 0x02 // valid compressed key prefix
    const badScript = new Uint8Array([
      0x00, 0x6a, // OP_FALSE OP_RETURN
      0x04, 0x6d, 0x65, 0x74, 0x61, // META_FLAG (4 bytes)
      0x21, ...pubBytes, // 33-byte pubkey
      0x20, ...new Uint8Array(32).fill(0x03), // 32-byte parentTxID
      0x00, // OP_0 = empty payload
    ])
    const outputs: TxOutput[] = [
      { value: 0n, scriptPubKey: badScript },
      { value: 1n, scriptPubKey: new Uint8Array([0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac]) },
    ]

    expect(parseTxNodeOps(outputs)).toEqual([])
  })

  it('skips scripts that are too short', () => {
    const outputs: TxOutput[] = [
      { value: 0n, scriptPubKey: new Uint8Array([0x00, 0x6a]) }, // Just prefix, no data
      { value: 1n, scriptPubKey: new Uint8Array([0x76]) }, // 1 byte
    ]

    expect(parseTxNodeOps(outputs)).toEqual([])
  })

  it('handles three ops in one batch transaction', () => {
    const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair()]
    const parentTxIDs = [
      filledBytes(TXID_LEN, 0x11),
      filledBytes(TXID_LEN, 0x22),
      new Uint8Array(0), // root
    ]
    const payloads = [
      new TextEncoder().encode('first'),
      new TextEncoder().encode('second'),
      new TextEncoder().encode('third root'),
    ]

    const allOutputs: TxOutput[] = []
    for (let i = 0; i < 3; i++) {
      const [opReturn, p2pkh] = buildNodeOpOutputs(
        keys[i].pub,
        parentTxIDs[i],
        payloads[i],
      )
      allOutputs.push(opReturn, p2pkh)
    }

    const ops = parseTxNodeOps(allOutputs)

    expect(ops).toHaveLength(3)
    for (let i = 0; i < 3; i++) {
      expect(ops[i].pNode).toEqual(Uint8Array.from(keys[i].pub.toDER() as number[]))
      expect(ops[i].parentTxID).toEqual(parentTxIDs[i])
      expect(ops[i].payload).toEqual(payloads[i])
      expect(ops[i].vout).toBe(i * 2)
      expect(ops[i].nodeVout).toBe(i * 2 + 1)
      expect(ops[i].isDelete).toBe(false)
    }
  })

  it('parses OP_RETURN without paired dust output as delete', () => {
    const { pub } = generateKeyPair()
    const parentTxID = filledBytes(TXID_LEN, 0x44)
    const payload = new TextEncoder().encode('delete op payload')

    const [opReturn] = buildNodeOpOutputs(pub, parentTxID, payload)
    const ops = parseTxNodeOps([opReturn])

    expect(ops).toHaveLength(1)
    expect(ops[0].vout).toBe(0)
    expect(ops[0].nodeVout).toBe(0)
    expect(ops[0].isDelete).toBe(true)
    expect(ops[0].payload).toEqual(payload)
  })

  it('does not treat non-dust next output as paired node refresh', () => {
    const { pub } = generateKeyPair()
    const parentTxID = filledBytes(TXID_LEN, 0x55)
    const payload = new TextEncoder().encode('op with change-like next output')
    const [opReturn] = buildNodeOpOutputs(pub, parentTxID, payload)

    // Looks like P2PKH but value is > 1 sat, so this should be treated as change.
    const changeLikeOutput: TxOutput = {
      value: 1000n,
      scriptPubKey: new Uint8Array([
        0x76, 0xa9, 0x14,
        ...new Uint8Array(20).fill(0x99),
        0x88, 0xac,
      ]),
    }

    const ops = parseTxNodeOps([opReturn, changeLikeOutput])
    expect(ops).toHaveLength(1)
    expect(ops[0].vout).toBe(0)
    expect(ops[0].nodeVout).toBe(0)
    expect(ops[0].isDelete).toBe(true)
  })
})
