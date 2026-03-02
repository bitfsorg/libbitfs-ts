import { describe, it, expect } from 'vitest'
import { listDirectory, findChild, addChild, removeChild, renameChild, nextChildIndex } from '../directory.js'
import { createNode, NodeType } from '../types.js'

/** Creates a test pubkey filled with a byte value. */
function testPubKey(fill: number): Uint8Array {
  const pk = new Uint8Array(33)
  pk[0] = 0x02
  for (let i = 1; i < 33; i++) pk[i] = fill
  return pk
}

function makeDir(): ReturnType<typeof createNode> {
  const node = createNode()
  node.type = NodeType.Dir
  return node
}

describe('listDirectory', () => {
  it('returns empty list for empty directory', () => {
    const dir = makeDir()
    const entries = listDirectory(dir)
    expect(entries).toHaveLength(0)
  })

  it('returns a copy of children', () => {
    const dir = makeDir()
    addChild(dir, 'a.txt', NodeType.File, testPubKey(0x01), false)
    const entries = listDirectory(dir)
    entries.pop() // mutate the copy
    expect(dir.children).toHaveLength(1) // original unchanged
  })

  it('throws for non-directory node', () => {
    const file = createNode()
    file.type = NodeType.File
    expect(() => listDirectory(file)).toThrow('not a directory')
  })
})

describe('findChild', () => {
  it('finds existing child', () => {
    const dir = makeDir()
    addChild(dir, 'readme.md', NodeType.File, testPubKey(0x01), false)
    const found = findChild(dir, 'readme.md')
    expect(found).not.toBeNull()
    expect(found!.name).toBe('readme.md')
  })

  it('returns null for missing child', () => {
    const dir = makeDir()
    expect(findChild(dir, 'nonexistent')).toBeNull()
  })

  it('returns null for non-directory node', () => {
    const file = createNode()
    file.type = NodeType.File
    expect(findChild(file, 'anything')).toBeNull()
  })
})

describe('addChild', () => {
  it('adds a file child with correct index', () => {
    const dir = makeDir()
    const entry = addChild(dir, 'hello.txt', NodeType.File, testPubKey(0x01), false)
    expect(entry.index).toBe(0)
    expect(entry.name).toBe('hello.txt')
    expect(entry.type).toBe(NodeType.File)
    expect(entry.hardened).toBe(false)
    expect(dir.nextChildIndex).toBe(1)
  })

  it('increments index for each child', () => {
    const dir = makeDir()
    addChild(dir, 'a', NodeType.File, testPubKey(0x01), false)
    addChild(dir, 'b', NodeType.File, testPubKey(0x02), false)
    const c = addChild(dir, 'c', NodeType.File, testPubKey(0x03), false)
    expect(c.index).toBe(2)
    expect(dir.nextChildIndex).toBe(3)
  })

  it('rejects duplicate name', () => {
    const dir = makeDir()
    addChild(dir, 'dup', NodeType.File, testPubKey(0x01), false)
    expect(() => addChild(dir, 'dup', NodeType.File, testPubKey(0x02), false)).toThrow('already exists')
  })

  it('rejects invalid names', () => {
    const dir = makeDir()
    const pk = testPubKey(0x01)
    expect(() => addChild(dir, '', NodeType.File, pk, false)).toThrow('empty')
    expect(() => addChild(dir, '.', NodeType.File, pk, false)).toThrow('reserved')
    expect(() => addChild(dir, '..', NodeType.File, pk, false)).toThrow('reserved')
    expect(() => addChild(dir, 'a/b', NodeType.File, pk, false)).toThrow('path separator')
    expect(() => addChild(dir, 'a\x00b', NodeType.File, pk, false)).toThrow('null byte')
  })

  it('rejects wrong pubkey length', () => {
    const dir = makeDir()
    expect(() => addChild(dir, 'file', NodeType.File, new Uint8Array(32), false)).toThrow('public key')
  })

  it('rejects hard links to directories', () => {
    const dir = makeDir()
    const pk = testPubKey(0x01)
    addChild(dir, 'dir1', NodeType.Dir, pk, false)
    expect(() => addChild(dir, 'dir2', NodeType.Dir, pk, false)).toThrow('hard-link')
  })

  it('rejects adding to non-directory', () => {
    const file = createNode()
    file.type = NodeType.File
    expect(() => addChild(file, 'child', NodeType.File, testPubKey(0x01), false)).toThrow('not a directory')
  })

  it('auto-recomputes merkle root on add', () => {
    const dir = makeDir()
    expect(dir.merkleRoot).toBeNull()
    addChild(dir, 'a', NodeType.File, testPubKey(0x01), false)
    expect(dir.merkleRoot).not.toBeNull()
    expect(dir.merkleRoot!).toHaveLength(32)
  })
})

describe('removeChild', () => {
  it('removes existing child', () => {
    const dir = makeDir()
    addChild(dir, 'victim', NodeType.File, testPubKey(0x01), false)
    expect(dir.children).toHaveLength(1)
    removeChild(dir, 'victim')
    expect(dir.children).toHaveLength(0)
  })

  it('does not decrement nextChildIndex', () => {
    const dir = makeDir()
    addChild(dir, 'a', NodeType.File, testPubKey(0x01), false)
    addChild(dir, 'b', NodeType.File, testPubKey(0x02), false)
    expect(dir.nextChildIndex).toBe(2)
    removeChild(dir, 'a')
    expect(dir.nextChildIndex).toBe(2) // never decrements
  })

  it('throws for non-existent child', () => {
    const dir = makeDir()
    expect(() => removeChild(dir, 'ghost')).toThrow('not found')
  })

  it('auto-recomputes merkle root on remove', () => {
    const dir = makeDir()
    addChild(dir, 'a', NodeType.File, testPubKey(0x01), false)
    const rootBefore = dir.merkleRoot
    addChild(dir, 'b', NodeType.File, testPubKey(0x02), false)
    expect(dir.merkleRoot).not.toEqual(rootBefore)

    removeChild(dir, 'b')
    // After removing 'b', merkle root should be back to single-child root
    expect(dir.merkleRoot).toEqual(rootBefore)
  })

  it('merkle root becomes null when all children removed', () => {
    const dir = makeDir()
    addChild(dir, 'only', NodeType.File, testPubKey(0x01), false)
    removeChild(dir, 'only')
    expect(dir.merkleRoot).toBeNull()
  })
})

describe('renameChild', () => {
  it('renames existing child', () => {
    const dir = makeDir()
    addChild(dir, 'old', NodeType.File, testPubKey(0x01), false)
    renameChild(dir, 'old', 'new')
    expect(findChild(dir, 'old')).toBeNull()
    expect(findChild(dir, 'new')).not.toBeNull()
  })

  it('rejects duplicate new name', () => {
    const dir = makeDir()
    addChild(dir, 'a', NodeType.File, testPubKey(0x01), false)
    addChild(dir, 'b', NodeType.File, testPubKey(0x02), false)
    expect(() => renameChild(dir, 'a', 'b')).toThrow('already exists')
  })

  it('rejects invalid new name', () => {
    const dir = makeDir()
    addChild(dir, 'a', NodeType.File, testPubKey(0x01), false)
    expect(() => renameChild(dir, 'a', '')).toThrow('empty')
    expect(() => renameChild(dir, 'a', '.')).toThrow('reserved')
  })

  it('throws for non-existent old name', () => {
    const dir = makeDir()
    expect(() => renameChild(dir, 'ghost', 'new')).toThrow('not found')
  })

  it('auto-recomputes merkle root on rename', () => {
    const dir = makeDir()
    addChild(dir, 'a', NodeType.File, testPubKey(0x01), false)
    const rootBefore = new Uint8Array(dir.merkleRoot!)
    renameChild(dir, 'a', 'b')
    expect(dir.merkleRoot).not.toBeNull()
    // Merkle root changes because the entry name changed
    expect(dir.merkleRoot!).not.toEqual(rootBefore)
  })
})

describe('nextChildIndex', () => {
  it('returns current next index', () => {
    const dir = makeDir()
    expect(nextChildIndex(dir)).toBe(0)
    addChild(dir, 'a', NodeType.File, testPubKey(0x01), false)
    expect(nextChildIndex(dir)).toBe(1)
  })

  it('throws for non-directory', () => {
    const file = createNode()
    file.type = NodeType.File
    expect(() => nextChildIndex(file)).toThrow('not a directory')
  })
})
