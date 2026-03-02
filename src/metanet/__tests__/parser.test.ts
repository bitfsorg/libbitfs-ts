import { describe, it, expect } from 'vitest'
import { serializePayload, deserializePayload, parsePayload } from '../parser.js'
import { createNode, NodeType, OpType, AccessLevel, LinkType, ISOStatus, CompressionScheme } from '../types.js'
import type { Node, ChildEntry, ISOConfig } from '../types.js'

/** Creates a test pubkey filled with a byte value. */
function testPubKey(fill: number): Uint8Array {
  const pk = new Uint8Array(33)
  pk[0] = 0x02
  for (let i = 1; i < 33; i++) pk[i] = fill
  return pk
}

/** Creates a test 32-byte hash. */
function testHash(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

describe('serializePayload / parsePayload round-trip', () => {
  it('round-trips minimal file node', () => {
    const node = createNode()
    node.version = 1
    node.type = NodeType.File
    node.op = OpType.Create

    const payload = serializePayload(node)
    const parsed = parsePayload(payload)

    expect(parsed.version).toBe(1)
    expect(parsed.type).toBe(NodeType.File)
    expect(parsed.op).toBe(OpType.Create)
    expect(parsed.access).toBe(AccessLevel.Private) // default
    expect(parsed.index).toBe(0)
  })

  it('round-trips file node with all basic fields', () => {
    const node = createNode()
    node.version = 2
    node.type = NodeType.File
    node.op = OpType.Update
    node.mimeType = 'application/pdf'
    node.fileSize = 1024n * 1024n
    node.keyHash = testHash(0xab)
    node.access = AccessLevel.Paid
    node.pricePerKB = 100n
    node.timestamp = 1700000000n
    node.parent = testPubKey(0x11)
    node.index = 5
    node.domain = 'example.com'
    node.keywords = 'test document'
    node.description = 'A test file'
    node.encrypted = true
    node.onChain = true
    node.compression = CompressionScheme.GZIP
    node.cltvHeight = 800000
    node.revenueShare = 25
    node.networkName = 'mainnet'

    const payload = serializePayload(node)
    const parsed = parsePayload(payload)

    expect(parsed.version).toBe(2)
    expect(parsed.type).toBe(NodeType.File)
    expect(parsed.op).toBe(OpType.Update)
    expect(parsed.mimeType).toBe('application/pdf')
    expect(parsed.fileSize).toBe(1024n * 1024n)
    expect(parsed.keyHash).toEqual(testHash(0xab))
    expect(parsed.access).toBe(AccessLevel.Paid)
    expect(parsed.pricePerKB).toBe(100n)
    expect(parsed.timestamp).toBe(1700000000n)
    expect(parsed.parent).toEqual(testPubKey(0x11))
    expect(parsed.index).toBe(5)
    expect(parsed.domain).toBe('example.com')
    expect(parsed.keywords).toBe('test document')
    expect(parsed.description).toBe('A test file')
    expect(parsed.encrypted).toBe(true)
    expect(parsed.onChain).toBe(true)
    expect(parsed.compression).toBe(CompressionScheme.GZIP)
    expect(parsed.cltvHeight).toBe(800000)
    expect(parsed.revenueShare).toBe(25)
    expect(parsed.networkName).toBe('mainnet')
  })

  it('round-trips directory node with children', () => {
    const node = createNode()
    node.version = 1
    node.type = NodeType.Dir
    node.op = OpType.Create
    node.children = [
      { index: 0, name: 'file1.txt', type: NodeType.File, pubKey: testPubKey(0x01), hardened: false },
      { index: 1, name: 'subdir', type: NodeType.Dir, pubKey: testPubKey(0x02), hardened: true },
      { index: 2, name: 'link', type: NodeType.Link, pubKey: testPubKey(0x03), hardened: false },
    ]
    node.nextChildIndex = 3
    node.merkleRoot = testHash(0xcc)

    const payload = serializePayload(node)
    const parsed = parsePayload(payload)

    expect(parsed.type).toBe(NodeType.Dir)
    expect(parsed.children).toHaveLength(3)
    expect(parsed.children[0].name).toBe('file1.txt')
    expect(parsed.children[0].type).toBe(NodeType.File)
    expect(parsed.children[0].hardened).toBe(false)
    expect(parsed.children[1].name).toBe('subdir')
    expect(parsed.children[1].type).toBe(NodeType.Dir)
    expect(parsed.children[1].hardened).toBe(true)
    expect(parsed.children[2].name).toBe('link')
    expect(parsed.children[2].type).toBe(NodeType.Link)
    expect(parsed.nextChildIndex).toBe(3)
    expect(parsed.merkleRoot).toEqual(testHash(0xcc))
  })

  it('round-trips link node', () => {
    const node = createNode()
    node.version = 1
    node.type = NodeType.Link
    node.op = OpType.Create
    node.linkTarget = testPubKey(0x55)
    node.linkType = LinkType.SoftRemote
    node.domain = 'remote.example.com'

    const payload = serializePayload(node)
    const parsed = parsePayload(payload)

    expect(parsed.type).toBe(NodeType.Link)
    expect(parsed.linkTarget).toEqual(testPubKey(0x55))
    expect(parsed.linkType).toBe(LinkType.SoftRemote)
    expect(parsed.domain).toBe('remote.example.com')
  })

  it('round-trips content TxIDs', () => {
    const node = createNode()
    node.version = 1
    node.type = NodeType.File
    node.op = OpType.Create
    node.contentTxIDs = [testHash(0x01), testHash(0x02), testHash(0x03)]

    const payload = serializePayload(node)
    const parsed = parsePayload(payload)

    expect(parsed.contentTxIDs).toHaveLength(3)
    expect(parsed.contentTxIDs[0]).toEqual(testHash(0x01))
    expect(parsed.contentTxIDs[1]).toEqual(testHash(0x02))
    expect(parsed.contentTxIDs[2]).toEqual(testHash(0x03))
  })

  it('round-trips encrypted payload', () => {
    const encPayload = new Uint8Array(64)
    for (let i = 0; i < 64; i++) encPayload[i] = i

    const node = createNode()
    node.version = 1
    node.type = NodeType.File
    node.op = OpType.Create
    node.encPayload = encPayload

    const payload = serializePayload(node)
    const parsed = parsePayload(payload)

    expect(parsed.encPayload).toEqual(encPayload)
  })

  it('round-trips metadata', () => {
    const node = createNode()
    node.version = 1
    node.type = NodeType.File
    node.op = OpType.Create
    node.metadata = new Map([
      ['author', 'alice'],
      ['license', 'MIT'],
    ])

    const payload = serializePayload(node)
    const parsed = parsePayload(payload)

    expect(parsed.metadata.size).toBe(2)
    expect(parsed.metadata.get('author')).toBe('alice')
    expect(parsed.metadata.get('license')).toBe('MIT')
  })

  it('round-trips extended fields', () => {
    const node = createNode()
    node.version = 1
    node.type = NodeType.File
    node.op = OpType.Create
    node.versionLog = testPubKey(0xaa)
    node.shareList = testPubKey(0xbb)
    node.chunkIndex = 3
    node.totalChunks = 10
    node.recombinationHash = testHash(0xdd)
    node.rabinSignature = new Uint8Array([1, 2, 3, 4, 5])
    node.rabinPubKey = new Uint8Array([6, 7, 8, 9])
    node.registryTxID = testHash(0xee)
    node.registryVout = 2
    node.aclRef = new Uint8Array([0xaa, 0xbb, 0xcc])

    const payload = serializePayload(node)
    const parsed = parsePayload(payload)

    expect(parsed.versionLog).toEqual(testPubKey(0xaa))
    expect(parsed.shareList).toEqual(testPubKey(0xbb))
    expect(parsed.chunkIndex).toBe(3)
    expect(parsed.totalChunks).toBe(10)
    expect(parsed.recombinationHash).toEqual(testHash(0xdd))
    expect(parsed.rabinSignature).toEqual(new Uint8Array([1, 2, 3, 4, 5]))
    expect(parsed.rabinPubKey).toEqual(new Uint8Array([6, 7, 8, 9]))
    expect(parsed.registryTxID).toEqual(testHash(0xee))
    expect(parsed.registryVout).toBe(2)
    expect(parsed.aclRef).toEqual(new Uint8Array([0xaa, 0xbb, 0xcc]))
  })

  it('round-trips ISO config', () => {
    const addr = new Uint8Array(20)
    for (let i = 0; i < 20; i++) addr[i] = i + 1

    const node = createNode()
    node.version = 1
    node.type = NodeType.File
    node.op = OpType.Create
    node.iso = {
      totalShares: 10000n,
      pricePerShare: 500n,
      creatorAddr: addr,
      status: ISOStatus.Partial,
    }

    const payload = serializePayload(node)
    const parsed = parsePayload(payload)

    expect(parsed.iso).not.toBeNull()
    expect(parsed.iso!.totalShares).toBe(10000n)
    expect(parsed.iso!.pricePerShare).toBe(500n)
    expect(parsed.iso!.creatorAddr).toEqual(addr)
    expect(parsed.iso!.status).toBe(ISOStatus.Partial)
  })

  it('round-trips anchor node', () => {
    const node = createNode()
    node.version = 1
    node.type = NodeType.Anchor
    node.op = OpType.Create
    node.treeRootPNode = testPubKey(0x77)
    node.treeRootTxID = testHash(0x88)
    node.parentAnchorTxID = [testHash(0x99), testHash(0xaa)]
    node.author = 'Alice <alice@example.com>'
    node.commitMessage = 'Initial commit'
    node.gitCommitSHA = new Uint8Array(20).fill(0x42)
    node.fileMode = 0o100644

    const payload = serializePayload(node)
    const parsed = parsePayload(payload)

    expect(parsed.type).toBe(NodeType.Anchor)
    expect(parsed.treeRootPNode).toEqual(testPubKey(0x77))
    expect(parsed.treeRootTxID).toEqual(testHash(0x88))
    expect(parsed.parentAnchorTxID).toHaveLength(2)
    expect(parsed.parentAnchorTxID[0]).toEqual(testHash(0x99))
    expect(parsed.parentAnchorTxID[1]).toEqual(testHash(0xaa))
    expect(parsed.author).toBe('Alice <alice@example.com>')
    expect(parsed.commitMessage).toBe('Initial commit')
    expect(parsed.gitCommitSHA).toEqual(new Uint8Array(20).fill(0x42))
    expect(parsed.fileMode).toBe(0o100644)
  })

  it('silently skips unknown tags', () => {
    // Manually build a payload with an unknown tag (0xFF)
    const node = createNode()
    node.version = 42
    const validPayload = serializePayload(node)

    // Append unknown tag 0xFF with 3 bytes of data
    const unknownField = new Uint8Array([0xff, 3, 0xaa, 0xbb, 0xcc])
    const combined = new Uint8Array(validPayload.length + unknownField.length)
    combined.set(validPayload)
    combined.set(unknownField, validPayload.length)

    // Should parse without error, unknown tag silently ignored
    const parsed = parsePayload(combined)
    expect(parsed.version).toBe(42)
  })

  it('round-trips delete operation', () => {
    const node = createNode()
    node.version = 1
    node.type = NodeType.File
    node.op = OpType.Delete

    const payload = serializePayload(node)
    const parsed = parsePayload(payload)
    expect(parsed.op).toBe(OpType.Delete)
  })

  it('preserves boolean false values for encrypted/onChain', () => {
    const node = createNode()
    node.version = 1
    node.type = NodeType.File
    node.op = OpType.Create
    node.encrypted = false
    node.onChain = false

    const payload = serializePayload(node)
    const parsed = parsePayload(payload)

    // false values should not be serialized (matching Go: only if true)
    expect(parsed.encrypted).toBe(false)
    expect(parsed.onChain).toBe(false)
  })
})

describe('deserializePayload error handling', () => {
  it('throws on truncated value', () => {
    // tag=0x01, length=100, but only 2 bytes of data
    const data = new Uint8Array([0x01, 100, 0xaa, 0xbb])
    const node = createNode()
    expect(() => deserializePayload(data, node)).toThrow('truncated')
  })

  it('throws on invalid field length for uint32', () => {
    // tag=0x01 (VERSION, expects 4 bytes), length=3
    const data = new Uint8Array([0x01, 3, 0xaa, 0xbb, 0xcc])
    const node = createNode()
    expect(() => deserializePayload(data, node)).toThrow('expected 4 bytes')
  })

  it('throws on payload exceeding max size', () => {
    // tag=0x04 (MIME_TYPE, variable), length encoded as very large
    // We encode a varint representing MAX_PAYLOAD_SIZE + 1
    const node = createNode()
    // Build a fake large varint length
    const data = new Uint8Array([0x04, 0x81, 0x80, 0x80, 0x80, 0x08]) // ~2GB
    expect(() => deserializePayload(data, node)).toThrow('too large')
  })
})
