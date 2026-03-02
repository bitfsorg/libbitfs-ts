// metanet/resolve — Path resolution with ".." handling and link budget tracking

import type { Node, NodeStore, ResolveResult, ChildEntry } from './types.js'
import { NodeType, MAX_PATH_COMPONENTS, MAX_LINK_DEPTH, MAX_TOTAL_LINK_FOLLOWS } from './types.js'
import {
  MetanetError,
  ErrNilParam,
  ErrInvalidPath,
  ErrNotDirectory,
  ErrChildNotFound,
  ErrNodeNotFound,
  ErrTotalLinkBudgetExceeded,
} from './errors.js'
import { findChild } from './directory.js'
import { followLinkCounted } from './link.js'

/**
 * Splits a path string into components.
 * Handles leading/trailing slashes and multiple consecutive slashes.
 * Returns empty array for root ("/").
 */
export function splitPath(path: string): string[] {
  if (path === '') {
    throw ErrInvalidPath()
  }

  // Remove leading slash (absolute path)
  let p = path
  if (p.startsWith('/')) p = p.slice(1)
  // Remove trailing slash
  if (p.endsWith('/')) p = p.slice(0, -1)

  if (p === '') {
    // Was just "/" - root
    return []
  }

  const parts = p.split('/')
  // Filter empty components (from consecutive slashes)
  return parts.filter((s) => s !== '')
}

/**
 * Resolves a filesystem path starting from a root node.
 * Handles directory traversal, soft link following (per-link max depth 10),
 * global link budget of 40 total follows, and "." / ".." navigation.
 * ".." cannot escape above the root.
 */
export async function resolvePath(
  store: NodeStore,
  root: Node,
  pathComponents: string[],
): Promise<ResolveResult> {
  // Empty path returns root
  if (pathComponents.length === 0) {
    return {
      node: root,
      entry: null,
      parent: null,
      path: [],
    }
  }

  if (pathComponents.length > MAX_PATH_COMPONENTS) {
    throw new MetanetError(
      `${ErrInvalidPath().message}: path too deep (${pathComponents.length} components, max ${MAX_PATH_COMPONENTS})`,
      ErrInvalidPath().code,
    )
  }

  // Validate path components
  for (const comp of pathComponents) {
    if (comp === '') {
      throw new MetanetError(`${ErrInvalidPath().message}: empty component in path`, ErrInvalidPath().code)
    }
  }

  // Track traversal for ".." navigation
  interface StackEntry {
    node: Node
    entry: ChildEntry | null
    name: string
  }

  const stack: StackEntry[] = [{ node: root, entry: null, name: '' }]
  let current = root
  let currentEntry: ChildEntry | null = null
  const resolvedPath: string[] = []
  let totalLinkFollows = 0

  for (const component of pathComponents) {
    if (component === '.') {
      // Stay in current directory
      continue
    }

    if (component === '..') {
      // Navigate to parent
      if (stack.length <= 1) {
        // Already at root, ".." stays at root (cannot escape)
        continue
      }
      stack.pop()
      const parent = stack[stack.length - 1]
      current = parent.node
      currentEntry = parent.entry
      if (resolvedPath.length > 0) {
        resolvedPath.pop()
      }
      continue
    }

    // Current must be a directory to traverse into
    if (current.type !== NodeType.Dir) {
      throw new MetanetError(
        `${ErrNotDirectory().message}: "${component}" is not a directory`,
        ErrNotDirectory().code,
      )
    }

    // Find child by name
    const entry = findChild(current, component)
    if (entry === null) {
      throw new MetanetError(
        `${ErrChildNotFound().message}: "${component}" in directory`,
        ErrChildNotFound().code,
      )
    }

    // Resolve child node
    const childNode = await store.getNodeByPubKey(entry.pubKey)
    if (childNode === null) {
      throw new MetanetError(
        `${ErrNodeNotFound().message}: child "${component}"`,
        ErrNodeNotFound().code,
      )
    }

    // Follow links if needed, tracking against global budget
    let resolvedNode = childNode
    if (resolvedNode.type === NodeType.Link) {
      let remaining = MAX_LINK_DEPTH
      const budgetLeft = MAX_TOTAL_LINK_FOLLOWS - totalLinkFollows
      if (budgetLeft < remaining) {
        remaining = budgetLeft
      }
      if (remaining <= 0) {
        throw ErrTotalLinkBudgetExceeded()
      }

      const result = await followLinkCounted(store, resolvedNode, remaining)
      totalLinkFollows += result.hops
      if (totalLinkFollows > MAX_TOTAL_LINK_FOLLOWS) {
        throw ErrTotalLinkBudgetExceeded()
      }
      resolvedNode = result.node
    }

    stack.push({ node: resolvedNode, entry, name: component })
    current = resolvedNode
    currentEntry = entry
    resolvedPath.push(component)
  }

  let parentNode: Node | null = null
  if (stack.length > 1) {
    parentNode = stack[stack.length - 2].node
  }

  return {
    node: current,
    entry: currentEntry,
    parent: parentNode,
    path: resolvedPath,
  }
}
