import { describe, it, expect } from 'vitest'
import { splitPath, resolvePath } from '../resolve.js'
import { followLink, latestVersion, inheritPricePerKB } from '../link.js'
import { checkCLTVAccess } from '../cltv.js'
import { createNode, NodeType, LinkType, CLTVResult, AccessLevel } from '../types.js'
import type { Node, NodeStore } from '../types.js'

/** Creates a test pubkey filled with a byte value. */
function testPubKey(fill: number): Uint8Array {
  const pk = new Uint8Array(33)
  pk[0] = 0x02
  for (let i = 1; i < 33; i++) pk[i] = fill
  return pk
}

/** Creates a test 32-byte TxID. */
function testTxID(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

/** Creates a mock NodeStore from a map of hex(pubkey) -> Node. */
function mockStore(nodes: Map<string, Node>): NodeStore {
  const hexKey = (pk: Uint8Array) => Array.from(pk).map((b) => b.toString(16).padStart(2, '0')).join('')

  return {
    async getNodeByPubKey(pNode: Uint8Array): Promise<Node | null> {
      return nodes.get(hexKey(pNode)) ?? null
    },
    async getNodeByTxID(txID: Uint8Array): Promise<Node | null> {
      for (const node of nodes.values()) {
        if (bytesEqual(node.txID, txID)) return node
      }
      return null
    },
    async getNodeVersions(pNode: Uint8Array): Promise<Node[]> {
      const node = nodes.get(hexKey(pNode))
      return node ? [node] : []
    },
    async getChildNodes(dirNode: Node): Promise<Node[]> {
      const result: Node[] = []
      for (const child of dirNode.children) {
        const node = nodes.get(hexKey(child.pubKey))
        if (node) result.push(node)
      }
      return result
    },
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

function hexKey(pk: Uint8Array): string {
  return Array.from(pk).map((b) => b.toString(16).padStart(2, '0')).join('')
}

// --- splitPath tests ---

describe('splitPath', () => {
  it('splits simple path', () => {
    expect(splitPath('/dir/file')).toEqual(['dir', 'file'])
  })

  it('handles root path', () => {
    expect(splitPath('/')).toEqual([])
  })

  it('strips leading and trailing slashes', () => {
    expect(splitPath('/a/b/c/')).toEqual(['a', 'b', 'c'])
  })

  it('filters empty components from consecutive slashes', () => {
    expect(splitPath('/a//b///c')).toEqual(['a', 'b', 'c'])
  })

  it('handles relative path', () => {
    expect(splitPath('a/b')).toEqual(['a', 'b'])
  })

  it('handles path with dots', () => {
    expect(splitPath('/a/./b/../c')).toEqual(['a', '.', 'b', '..', 'c'])
  })

  it('throws on empty path', () => {
    expect(() => splitPath('')).toThrow('invalid path')
  })
})

// --- resolvePath tests ---

describe('resolvePath', () => {
  it('resolves empty path to root', async () => {
    const root = createNode()
    root.type = NodeType.Dir
    root.pNode = testPubKey(0x01)
    const store = mockStore(new Map())

    const result = await resolvePath(store, root, [])
    expect(result.node).toBe(root)
    expect(result.entry).toBeNull()
    expect(result.parent).toBeNull()
    expect(result.path).toEqual([])
  })

  it('resolves simple path /dir/file', async () => {
    const rootPK = testPubKey(0x01)
    const dirPK = testPubKey(0x02)
    const filePK = testPubKey(0x03)

    const root = createNode()
    root.type = NodeType.Dir
    root.pNode = rootPK
    root.children = [{ index: 0, name: 'dir', type: NodeType.Dir, pubKey: dirPK, hardened: false }]

    const dir = createNode()
    dir.type = NodeType.Dir
    dir.pNode = dirPK
    dir.children = [{ index: 0, name: 'file', type: NodeType.File, pubKey: filePK, hardened: false }]

    const file = createNode()
    file.type = NodeType.File
    file.pNode = filePK
    file.mimeType = 'text/plain'

    const nodes = new Map<string, Node>()
    nodes.set(hexKey(dirPK), dir)
    nodes.set(hexKey(filePK), file)
    const store = mockStore(nodes)

    const result = await resolvePath(store, root, ['dir', 'file'])
    expect(result.node.mimeType).toBe('text/plain')
    expect(result.entry).not.toBeNull()
    expect(result.entry!.name).toBe('file')
    expect(result.parent).toBe(dir)
    expect(result.path).toEqual(['dir', 'file'])
  })

  it('handles ".." navigation', async () => {
    const rootPK = testPubKey(0x01)
    const dirPK = testPubKey(0x02)
    const filePK = testPubKey(0x03)

    const root = createNode()
    root.type = NodeType.Dir
    root.pNode = rootPK
    root.children = [
      { index: 0, name: 'dir', type: NodeType.Dir, pubKey: dirPK, hardened: false },
      { index: 1, name: 'top_file', type: NodeType.File, pubKey: filePK, hardened: false },
    ]

    const dir = createNode()
    dir.type = NodeType.Dir
    dir.pNode = dirPK
    dir.children = []

    const topFile = createNode()
    topFile.type = NodeType.File
    topFile.pNode = filePK
    topFile.mimeType = 'application/pdf'

    const nodes = new Map<string, Node>()
    nodes.set(hexKey(dirPK), dir)
    nodes.set(hexKey(filePK), topFile)
    const store = mockStore(nodes)

    // /dir/../top_file => /top_file
    const result = await resolvePath(store, root, ['dir', '..', 'top_file'])
    expect(result.node.mimeType).toBe('application/pdf')
    expect(result.path).toEqual(['top_file'])
  })

  it('".." at root stays at root', async () => {
    const root = createNode()
    root.type = NodeType.Dir
    root.pNode = testPubKey(0x01)
    const store = mockStore(new Map())

    const result = await resolvePath(store, root, ['..', '..'])
    expect(result.node).toBe(root)
    expect(result.path).toEqual([])
  })

  it('"." stays in current directory', async () => {
    const root = createNode()
    root.type = NodeType.Dir
    root.pNode = testPubKey(0x01)
    const store = mockStore(new Map())

    const result = await resolvePath(store, root, ['.'])
    expect(result.node).toBe(root)
  })

  it('resolves soft link to target', async () => {
    const rootPK = testPubKey(0x01)
    const linkPK = testPubKey(0x02)
    const targetPK = testPubKey(0x03)

    const root = createNode()
    root.type = NodeType.Dir
    root.pNode = rootPK
    root.children = [{ index: 0, name: 'link', type: NodeType.Link, pubKey: linkPK, hardened: false }]

    const link = createNode()
    link.type = NodeType.Link
    link.pNode = linkPK
    link.linkType = LinkType.Soft
    link.linkTarget = targetPK

    const target = createNode()
    target.type = NodeType.File
    target.pNode = targetPK
    target.mimeType = 'image/png'

    const nodes = new Map<string, Node>()
    nodes.set(hexKey(linkPK), link)
    nodes.set(hexKey(targetPK), target)
    const store = mockStore(nodes)

    const result = await resolvePath(store, root, ['link'])
    expect(result.node.mimeType).toBe('image/png')
  })

  it('throws for non-existent child', async () => {
    const root = createNode()
    root.type = NodeType.Dir
    root.pNode = testPubKey(0x01)
    const store = mockStore(new Map())

    await expect(resolvePath(store, root, ['nonexistent'])).rejects.toThrow('not found')
  })

  it('throws for traversal through non-directory', async () => {
    const rootPK = testPubKey(0x01)
    const filePK = testPubKey(0x02)

    const root = createNode()
    root.type = NodeType.Dir
    root.pNode = rootPK
    root.children = [{ index: 0, name: 'file', type: NodeType.File, pubKey: filePK, hardened: false }]

    const file = createNode()
    file.type = NodeType.File
    file.pNode = filePK

    const nodes = new Map<string, Node>()
    nodes.set(hexKey(filePK), file)
    const store = mockStore(nodes)

    await expect(resolvePath(store, root, ['file', 'subpath'])).rejects.toThrow('not a directory')
  })

  it('throws when path exceeds max components', async () => {
    const root = createNode()
    root.type = NodeType.Dir
    root.pNode = testPubKey(0x01)
    const store = mockStore(new Map())

    const longPath = Array.from({ length: 300 }, (_, i) => `c${i}`)
    await expect(resolvePath(store, root, longPath)).rejects.toThrow('too deep')
  })

  it('throws when empty component in path', async () => {
    const root = createNode()
    root.type = NodeType.Dir
    root.pNode = testPubKey(0x01)
    const store = mockStore(new Map())

    await expect(resolvePath(store, root, ['a', '', 'b'])).rejects.toThrow('empty component')
  })
})

// --- followLink tests ---

describe('followLink', () => {
  it('follows a single soft link', async () => {
    const linkPK = testPubKey(0x01)
    const targetPK = testPubKey(0x02)

    const link = createNode()
    link.type = NodeType.Link
    link.pNode = linkPK
    link.linkType = LinkType.Soft
    link.linkTarget = targetPK

    const target = createNode()
    target.type = NodeType.File
    target.pNode = targetPK
    target.mimeType = 'text/html'

    const nodes = new Map<string, Node>()
    nodes.set(hexKey(targetPK), target)
    const store = mockStore(nodes)

    const result = await followLink(store, link)
    expect(result.mimeType).toBe('text/html')
  })

  it('follows a chain of links', async () => {
    const link1PK = testPubKey(0x01)
    const link2PK = testPubKey(0x02)
    const targetPK = testPubKey(0x03)

    const link1 = createNode()
    link1.type = NodeType.Link
    link1.pNode = link1PK
    link1.linkType = LinkType.Soft
    link1.linkTarget = link2PK

    const link2 = createNode()
    link2.type = NodeType.Link
    link2.pNode = link2PK
    link2.linkType = LinkType.Soft
    link2.linkTarget = targetPK

    const target = createNode()
    target.type = NodeType.File
    target.pNode = targetPK

    const nodes = new Map<string, Node>()
    nodes.set(hexKey(link2PK), link2)
    nodes.set(hexKey(targetPK), target)
    const store = mockStore(nodes)

    const result = await followLink(store, link1)
    expect(result.type).toBe(NodeType.File)
  })

  it('throws on link depth exceeded', async () => {
    // Create a circular chain of 11 links
    const pks: Uint8Array[] = []
    const links: Node[] = []
    for (let i = 0; i < 11; i++) {
      pks.push(testPubKey(i + 1))
    }
    for (let i = 0; i < 11; i++) {
      const link = createNode()
      link.type = NodeType.Link
      link.pNode = pks[i]
      link.linkType = LinkType.Soft
      link.linkTarget = pks[(i + 1) % 11]
      links.push(link)
    }

    const nodes = new Map<string, Node>()
    for (let i = 0; i < 11; i++) {
      nodes.set(hexKey(pks[i]), links[i])
    }
    const store = mockStore(nodes)

    await expect(followLink(store, links[0])).rejects.toThrow('link depth exceeded')
  })

  it('throws on remote link', async () => {
    const link = createNode()
    link.type = NodeType.Link
    link.linkType = LinkType.SoftRemote
    link.domain = 'remote.example.com'

    const store = mockStore(new Map())
    await expect(followLink(store, link)).rejects.toThrow('remote link not supported')
  })

  it('throws on link with no target', async () => {
    const link = createNode()
    link.type = NodeType.Link
    link.linkType = LinkType.Soft
    link.linkTarget = new Uint8Array(0)

    const store = mockStore(new Map())
    await expect(followLink(store, link)).rejects.toThrow('no target')
  })

  it('throws on non-link node', async () => {
    const file = createNode()
    file.type = NodeType.File

    const store = mockStore(new Map())
    await expect(followLink(store, file)).rejects.toThrow('not a link')
  })
})

// --- latestVersion tests ---

describe('latestVersion', () => {
  it('returns null for empty array', () => {
    expect(latestVersion([])).toBeNull()
  })

  it('returns the only node', () => {
    const node = createNode()
    node.blockHeight = 100
    expect(latestVersion([node])).toBe(node)
  })

  it('picks highest block height', () => {
    const a = createNode()
    a.blockHeight = 100
    a.txID = testTxID(0x01)

    const b = createNode()
    b.blockHeight = 200
    b.txID = testTxID(0x02)

    expect(latestVersion([a, b])).toBe(b)
    expect(latestVersion([b, a])).toBe(b) // order independent
  })

  it('uses timestamp for same block height', () => {
    const a = createNode()
    a.blockHeight = 100
    a.timestamp = 1000n
    a.txID = testTxID(0x01)

    const b = createNode()
    b.blockHeight = 100
    b.timestamp = 2000n
    b.txID = testTxID(0x02)

    expect(latestVersion([a, b])).toBe(b)
  })

  it('uses TxID as tiebreaker for same height and timestamp', () => {
    const a = createNode()
    a.blockHeight = 100
    a.timestamp = 1000n
    a.txID = testTxID(0x01)

    const b = createNode()
    b.blockHeight = 100
    b.timestamp = 1000n
    b.txID = testTxID(0xff)

    expect(latestVersion([a, b])).toBe(b) // 0xff > 0x01
  })
})

// --- inheritPricePerKB tests ---

describe('inheritPricePerKB', () => {
  it('returns price from current node', async () => {
    const node = createNode()
    node.pricePerKB = 500n
    const store = mockStore(new Map())

    expect(await inheritPricePerKB(store, node)).toBe(500n)
  })

  it('inherits price from parent', async () => {
    const parentPK = testPubKey(0x01)
    const parent = createNode()
    parent.pNode = parentPK
    parent.pricePerKB = 300n

    const child = createNode()
    child.parent = parentPK
    child.pricePerKB = 0n

    const nodes = new Map<string, Node>()
    nodes.set(hexKey(parentPK), parent)
    const store = mockStore(nodes)

    expect(await inheritPricePerKB(store, child)).toBe(300n)
  })

  it('returns 0n if no price set anywhere', async () => {
    const root = createNode()
    root.pricePerKB = 0n
    root.parent = new Uint8Array(0) // root
    const store = mockStore(new Map())

    expect(await inheritPricePerKB(store, root)).toBe(0n)
  })
})

// --- checkCLTVAccess tests ---

describe('checkCLTVAccess', () => {
  it('returns Allowed when cltvHeight is 0 (no restriction)', () => {
    const node = createNode()
    node.cltvHeight = 0
    expect(checkCLTVAccess(node, 100)).toBe(CLTVResult.Allowed)
  })

  it('returns Allowed when currentHeight >= cltvHeight', () => {
    const node = createNode()
    node.cltvHeight = 500
    expect(checkCLTVAccess(node, 500)).toBe(CLTVResult.Allowed)
    expect(checkCLTVAccess(node, 600)).toBe(CLTVResult.Allowed)
  })

  it('returns Denied when currentHeight < cltvHeight', () => {
    const node = createNode()
    node.cltvHeight = 500
    expect(checkCLTVAccess(node, 499)).toBe(CLTVResult.Denied)
    expect(checkCLTVAccess(node, 0)).toBe(CLTVResult.Denied)
  })

  it('returns Denied for null node', () => {
    expect(checkCLTVAccess(null, 100)).toBe(CLTVResult.Denied)
    expect(checkCLTVAccess(undefined, 100)).toBe(CLTVResult.Denied)
  })
})
