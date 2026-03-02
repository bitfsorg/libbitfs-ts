// metanet/directory — Directory operations (list, find, add, remove, rename)

import type { Node, ChildEntry } from './types.js'
import { NodeType, COMPRESSED_PUBKEY_LEN, MAX_CHILD_NAME_LEN } from './types.js'
import {
  ErrNotDirectory,
  ErrNilParam,
  ErrInvalidName,
  ErrChildExists,
  ErrChildNotFound,
  ErrInvalidPubKey,
  ErrHardLinkToDirectory,
  MetanetError,
} from './errors.js'
import { computeDirectoryMerkleRoot } from './merkle.js'

/**
 * Returns the ChildEntry list of a directory node.
 * Returns a shallow copy to prevent external mutation.
 */
export function listDirectory(node: Node): ChildEntry[] {
  if (node.type !== NodeType.Dir) {
    throw new MetanetError(`${ErrNotDirectory.message}: node type is ${node.type}`, ErrNotDirectory.code)
  }
  return node.children.slice()
}

/**
 * Finds a child by name in a directory node's children list.
 * Returns the entry or null if not found.
 */
export function findChild(dirNode: Node, name: string): ChildEntry | null {
  if (dirNode.type !== NodeType.Dir) return null
  for (const child of dirNode.children) {
    if (child.name === name) return child
  }
  return null
}

/**
 * Adds a new ChildEntry to a directory node.
 * Allocates the next child index and increments NextChildIndex.
 * Auto-recomputes MerkleRoot.
 */
export function addChild(
  dirNode: Node,
  name: string,
  nodeType: NodeType,
  pubKey: Uint8Array,
  hardened: boolean,
): ChildEntry {
  if (dirNode.type !== NodeType.Dir) {
    throw new MetanetError(`${ErrNotDirectory.message}: node type is ${dirNode.type}`, ErrNotDirectory.code)
  }

  validateChildName(name)

  if (pubKey.length !== COMPRESSED_PUBKEY_LEN) {
    throw new MetanetError(`${ErrInvalidPubKey.message}: got ${pubKey.length} bytes`, ErrInvalidPubKey.code)
  }

  // Check for duplicate name
  for (const child of dirNode.children) {
    if (child.name === name) {
      throw new MetanetError(`${ErrChildExists.message}: "${name}"`, ErrChildExists.code)
    }
  }

  // Reject hard links to directories
  if (nodeType === NodeType.Dir) {
    for (const child of dirNode.children) {
      if (bytesEqual(child.pubKey, pubKey)) {
        throw new MetanetError(
          `${ErrHardLinkToDirectory.message}: cannot hard-link directories`,
          ErrHardLinkToDirectory.code,
        )
      }
    }
  }

  const entry: ChildEntry = {
    index: dirNode.nextChildIndex,
    name,
    type: nodeType,
    pubKey: new Uint8Array(COMPRESSED_PUBKEY_LEN),
    hardened,
  }
  entry.pubKey.set(pubKey)

  dirNode.children.push(entry)
  dirNode.nextChildIndex++
  recomputeMerkleRoot(dirNode)

  return dirNode.children[dirNode.children.length - 1]
}

/**
 * Removes a ChildEntry by name from a directory node.
 * Does NOT decrement NextChildIndex (deleted indices are never reused).
 * Auto-recomputes MerkleRoot.
 */
export function removeChild(dirNode: Node, name: string): void {
  if (dirNode.type !== NodeType.Dir) {
    throw new MetanetError(`${ErrNotDirectory.message}: node type is ${dirNode.type}`, ErrNotDirectory.code)
  }

  const idx = dirNode.children.findIndex((c) => c.name === name)
  if (idx === -1) {
    throw new MetanetError(`${ErrChildNotFound.message}: "${name}"`, ErrChildNotFound.code)
  }

  dirNode.children.splice(idx, 1)
  recomputeMerkleRoot(dirNode)
}

/**
 * Renames a ChildEntry within a directory.
 * Auto-recomputes MerkleRoot.
 */
export function renameChild(dirNode: Node, oldName: string, newName: string): void {
  if (dirNode.type !== NodeType.Dir) {
    throw new MetanetError(`${ErrNotDirectory.message}: node type is ${dirNode.type}`, ErrNotDirectory.code)
  }

  validateChildName(newName)

  // Check new name doesn't already exist
  for (const child of dirNode.children) {
    if (child.name === newName) {
      throw new MetanetError(`${ErrChildExists.message}: "${newName}"`, ErrChildExists.code)
    }
  }

  // Find and rename
  for (const child of dirNode.children) {
    if (child.name === oldName) {
      child.name = newName
      recomputeMerkleRoot(dirNode)
      return
    }
  }

  throw new MetanetError(`${ErrChildNotFound.message}: "${oldName}"`, ErrChildNotFound.code)
}

/**
 * Returns the next available child index for a directory.
 * This is the value that would be assigned to the next added child.
 */
export function nextChildIndex(dirNode: Node): number {
  if (dirNode.type !== NodeType.Dir) {
    throw new MetanetError(`${ErrNotDirectory.message}: node type is ${dirNode.type}`, ErrNotDirectory.code)
  }
  return dirNode.nextChildIndex
}

// --- Internal helpers ---

/** Recomputes the node's MerkleRoot from its current Children. */
function recomputeMerkleRoot(node: Node): void {
  node.merkleRoot = computeDirectoryMerkleRoot(node.children)
}

/** Validates a child name for directory entry use. */
function validateChildName(name: string): void {
  if (name === '') {
    throw new MetanetError(`${ErrInvalidName.message}: name is empty`, ErrInvalidName.code)
  }
  if (name.length > MAX_CHILD_NAME_LEN) {
    throw new MetanetError(
      `${ErrInvalidName.message}: name too long (${name.length} bytes, max ${MAX_CHILD_NAME_LEN})`,
      ErrInvalidName.code,
    )
  }
  if (name.includes('/')) {
    throw new MetanetError(`${ErrInvalidName.message}: name contains path separator`, ErrInvalidName.code)
  }
  if (name === '.' || name === '..') {
    throw new MetanetError(`${ErrInvalidName.message}: name is reserved`, ErrInvalidName.code)
  }
  if (name.includes('\x00')) {
    throw new MetanetError(`${ErrInvalidName.message}: name contains null byte`, ErrInvalidName.code)
  }
  // Check for control characters and Unicode format characters
  for (const ch of name) {
    const code = ch.codePointAt(0)!
    // Control characters: U+0000-U+001F, U+007F-U+009F
    if ((code <= 0x1f) || (code >= 0x7f && code <= 0x9f)) {
      throw new MetanetError(
        `${ErrInvalidName.message}: name contains control character U+${code.toString(16).padStart(4, '0').toUpperCase()}`,
        ErrInvalidName.code,
      )
    }
    // Unicode format characters (Cf category) — common ones
    if (
      (code >= 0x200b && code <= 0x200f) || // zero-width spaces and directional marks
      (code >= 0x202a && code <= 0x202e) || // bidi control
      (code >= 0x2060 && code <= 0x2069) || // word joiner, invisible separators
      code === 0xfeff || // BOM
      code === 0xad // soft hyphen
    ) {
      throw new MetanetError(
        `${ErrInvalidName.message}: name contains control or formatting character U+${code.toString(16).padStart(4, '0').toUpperCase()}`,
        ErrInvalidName.code,
      )
    }
  }
}

/** Compares two Uint8Arrays for equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}
