import { describe, it, expect } from 'vitest'
import { PrivateKey, PublicKey } from '@bsv/sdk'
import {
  META_FLAG,
  DUST_LIMIT,
  DEFAULT_FEE_RATE,
  COMPRESSED_PUB_KEY_LEN,
  TXID_LEN,
  buildOPReturnData,
  parseOPReturnData,
  estimateFee,
  estimateTxSize,
  NilParamError,
  InvalidPayloadError,
  InvalidParentTxIDError,
  InvalidOPReturnError,
  NotMetanetTxError,
} from '../index.js'

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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

describe('tx constants', () => {
  it('META_FLAG is "meta" in ASCII', () => {
    expect(META_FLAG).toEqual(new Uint8Array([0x6d, 0x65, 0x74, 0x61]))
  })

  it('DUST_LIMIT is 1 satoshi', () => {
    expect(DUST_LIMIT).toBe(1n)
  })

  it('DEFAULT_FEE_RATE is 100 sat/KB', () => {
    expect(DEFAULT_FEE_RATE).toBe(100n)
  })

  it('COMPRESSED_PUB_KEY_LEN is 33', () => {
    expect(COMPRESSED_PUB_KEY_LEN).toBe(33)
  })

  it('TXID_LEN is 32', () => {
    expect(TXID_LEN).toBe(32)
  })
})

// ---------------------------------------------------------------------------
// buildOPReturnData
// ---------------------------------------------------------------------------

describe('buildOPReturnData', () => {
  it('produces 4 pushes: MetaFlag, PNode(33B), ParentTxID(32B), Payload', () => {
    const { pub } = generateKeyPair()
    const parentTxID = filledBytes(32, 0xab)
    const payload = new TextEncoder().encode('test TLV payload')

    const pushes = buildOPReturnData(pub, parentTxID, payload)
    expect(pushes).toHaveLength(4)

    // pushdata[0]: MetaFlag
    expect(pushes[0]).toEqual(META_FLAG)

    // pushdata[1]: P_node (33 bytes compressed pubkey)
    expect(pushes[1]).toHaveLength(COMPRESSED_PUB_KEY_LEN)

    // pushdata[2]: TxID_parent
    expect(pushes[2]).toEqual(parentTxID)

    // pushdata[3]: payload
    expect(pushes[3]).toEqual(payload)
  })

  it('root node has empty parent TxID', () => {
    const { pub } = generateKeyPair()
    const payload = new TextEncoder().encode('root node payload')

    const pushes = buildOPReturnData(pub, new Uint8Array(0), payload)
    expect(pushes).toHaveLength(4)
    expect(pushes[2]).toHaveLength(0)
  })

  it('throws NilParamError for null pubKey', () => {
    const payload = new TextEncoder().encode('test')
    expect(() =>
      buildOPReturnData(null as unknown as PublicKey, new Uint8Array(0), payload),
    ).toThrow(NilParamError)
  })

  it('throws InvalidPayloadError for empty payload', () => {
    const { pub } = generateKeyPair()
    expect(() =>
      buildOPReturnData(pub, new Uint8Array(0), new Uint8Array(0)),
    ).toThrow(InvalidPayloadError)
  })

  it('throws InvalidParentTxIDError for wrong length parentTxID', () => {
    const { pub } = generateKeyPair()
    const payload = new TextEncoder().encode('test')
    expect(() =>
      buildOPReturnData(pub, new Uint8Array([0x01, 0x02]), payload),
    ).toThrow(InvalidParentTxIDError)
  })
})

// ---------------------------------------------------------------------------
// parseOPReturnData
// ---------------------------------------------------------------------------

describe('parseOPReturnData', () => {
  it('round-trips with buildOPReturnData (child node)', () => {
    const { pub } = generateKeyPair()
    const parentTxID = filledBytes(32, 0xab)
    const payload = new TextEncoder().encode('test payload data')

    const pushes = buildOPReturnData(pub, parentTxID, payload)
    const result = parseOPReturnData(pushes)

    expect(result.pNode).toEqual(Uint8Array.from(pub.toDER() as number[]))
    expect(result.parentTxID).toEqual(parentTxID)
    expect(result.payload).toEqual(payload)
  })

  it('round-trips with buildOPReturnData (root node)', () => {
    const { pub } = generateKeyPair()
    const payload = new TextEncoder().encode('root payload')

    const pushes = buildOPReturnData(pub, new Uint8Array(0), payload)
    const result = parseOPReturnData(pushes)

    expect(result.parentTxID).toHaveLength(0)
  })

  it('round-trips with large payload', () => {
    const { pub } = generateKeyPair()
    const parentTxID = filledBytes(32, 0xcd)
    const payload = filledBytes(10000, 0x78) // 'x'

    const pushes = buildOPReturnData(pub, parentTxID, payload)
    const result = parseOPReturnData(pushes)

    expect(result.pNode).toEqual(Uint8Array.from(pub.toDER() as number[]))
    expect(result.parentTxID).toEqual(parentTxID)
    expect(result.payload).toEqual(payload)
  })

  it('throws InvalidOPReturnError for too few pushes', () => {
    expect(() => parseOPReturnData([new Uint8Array([0x01])])).toThrow(
      InvalidOPReturnError,
    )
  })

  it('throws NotMetanetTxError for wrong MetaFlag', () => {
    expect(() =>
      parseOPReturnData([
        new Uint8Array([0xff, 0xff, 0xff, 0xff]),
        filledBytes(33, 0x02),
        filledBytes(32, 0x03),
        new TextEncoder().encode('payload'),
      ]),
    ).toThrow(NotMetanetTxError)
  })

  it('throws InvalidOPReturnError for invalid PNode length', () => {
    expect(() =>
      parseOPReturnData([
        META_FLAG,
        new Uint8Array([0x02, 0x03]), // too short
        filledBytes(32, 0x03),
        new TextEncoder().encode('payload'),
      ]),
    ).toThrow(InvalidOPReturnError)
  })

  it('throws InvalidOPReturnError for invalid parent TxID length', () => {
    expect(() =>
      parseOPReturnData([
        META_FLAG,
        filledBytes(33, 0x02),
        new Uint8Array([0x01, 0x02, 0x03]), // 3 bytes, not 0 or 32
        new TextEncoder().encode('payload'),
      ]),
    ).toThrow(InvalidOPReturnError)
  })

  it('throws InvalidOPReturnError for empty payload', () => {
    expect(() =>
      parseOPReturnData([
        META_FLAG,
        filledBytes(33, 0x02),
        filledBytes(32, 0x03),
        new Uint8Array(0), // empty
      ]),
    ).toThrow(InvalidOPReturnError)
  })
})

// ---------------------------------------------------------------------------
// Fee estimation
// ---------------------------------------------------------------------------

describe('estimateFee', () => {
  it('minimal tx (200 bytes, 1 sat/KB) returns >= 1', () => {
    const fee = estimateFee(200, 1n)
    expect(fee).toBeGreaterThanOrEqual(1n)
  })

  it('1KB tx at 1 sat/KB returns 1', () => {
    const fee = estimateFee(1000, 1n)
    expect(fee).toBe(1n)
  })

  it('2KB tx at 1 sat/KB returns 2', () => {
    const fee = estimateFee(2000, 1n)
    expect(fee).toBe(2n)
  })

  it('500B tx at 2 sat/KB returns 1', () => {
    const fee = estimateFee(500, 2n)
    expect(fee).toBe(1n)
  })

  it('0 rate uses default (100 sat/KB)', () => {
    const fee = estimateFee(1000, 0n)
    expect(fee).toBe(100n)
  })

  it('zero-size tx returns 0', () => {
    const fee = estimateFee(0, 1n)
    expect(fee).toBe(0n)
  })
})

describe('estimateTxSize', () => {
  it('returns positive for reasonable inputs', () => {
    const size = estimateTxSize(1, 3, 100)
    expect(size).toBeGreaterThan(0)
  })

  it('more inputs/outputs = larger size', () => {
    const size1 = estimateTxSize(1, 3, 100)
    const size2 = estimateTxSize(2, 4, 100)
    expect(size2).toBeGreaterThan(size1)
  })

  it('larger payload = larger size', () => {
    const size1 = estimateTxSize(1, 3, 100)
    const size2 = estimateTxSize(1, 3, 1000)
    expect(size2).toBeGreaterThan(size1)
  })

  it('zero inputs/outputs returns positive (base + opReturn overhead)', () => {
    const size = estimateTxSize(0, 0, 0)
    expect(size).toBeGreaterThan(0)
  })
})
