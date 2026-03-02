// metanet/link — Link following, version selection, price inheritance

import type { Node, NodeStore } from './types.js'
import { NodeType, LinkType, MAX_LINK_DEPTH } from './types.js'
import {
  MetanetError,
  ErrNotLink,
  ErrNilParam,
  ErrNodeNotFound,
  ErrLinkDepthExceeded,
  ErrRemoteLinkNotSupported,
} from './errors.js'

/**
 * Resolves a soft link to its target node.
 * SOFT: looks up target P_node for latest version.
 * SOFT_REMOTE: returns error (requires external resolution via DNS/Paymail).
 * Follows chains up to maxDepth (default MAX_LINK_DEPTH=10).
 */
export async function followLink(store: NodeStore, linkNode: Node, maxDepth?: number): Promise<Node> {
  if (linkNode.type !== NodeType.Link) {
    throw new MetanetError(`${ErrNotLink.message}: node type is ${linkNode.type}`, ErrNotLink.code)
  }

  const depth = maxDepth != null && maxDepth > 0 ? maxDepth : MAX_LINK_DEPTH

  let current = linkNode
  for (let i = 0; i < depth; i++) {
    if (current.type !== NodeType.Link) {
      // Resolved to a non-link node
      return current
    }

    if (current.linkType === LinkType.SoftRemote) {
      throw new MetanetError(
        `${ErrRemoteLinkNotSupported.message}: target=${current.domain}`,
        ErrRemoteLinkNotSupported.code,
      )
    }

    // Soft link: look up target by P_node
    if (current.linkTarget.length === 0) {
      throw new MetanetError(`${ErrNodeNotFound.message}: link has no target`, ErrNodeNotFound.code)
    }

    const target = await store.getNodeByPubKey(current.linkTarget)
    if (target === null) {
      throw new MetanetError(`${ErrNodeNotFound.message}: link target not found`, ErrNodeNotFound.code)
    }

    current = target
  }

  // If still on a link after maxDepth iterations, the chain is too deep
  if (current.type === NodeType.Link) {
    throw ErrLinkDepthExceeded
  }

  return current
}

/**
 * Resolves a soft link chain, returning the resolved node and the number of
 * link hops taken. maxHops limits the maximum hops allowed.
 * Used internally by path resolution to track global link budget.
 */
export async function followLinkCounted(
  store: NodeStore,
  linkNode: Node,
  maxHops: number,
): Promise<{ node: Node; hops: number }> {
  if (linkNode.type !== NodeType.Link) {
    return { node: linkNode, hops: 0 }
  }

  let current = linkNode
  let hops = 0

  while (hops < maxHops) {
    if (current.type !== NodeType.Link) {
      return { node: current, hops }
    }

    if (current.linkType === LinkType.SoftRemote) {
      throw new MetanetError(
        `${ErrRemoteLinkNotSupported.message}: target=${current.domain}`,
        ErrRemoteLinkNotSupported.code,
      )
    }

    if (current.linkTarget.length === 0) {
      throw new MetanetError(`${ErrNodeNotFound.message}: link has no target`, ErrNodeNotFound.code)
    }

    const target = await store.getNodeByPubKey(current.linkTarget)
    if (target === null) {
      throw new MetanetError(`${ErrNodeNotFound.message}: link target not found`, ErrNodeNotFound.code)
    }

    hops++
    current = target
  }

  if (current.type === NodeType.Link) {
    throw ErrLinkDepthExceeded
  }

  return { node: current, hops }
}

/**
 * Selects the latest version from a list of nodes with the same P_node.
 * Ordering: highest block height wins; within the same block, TTOR ordering
 * (higher Timestamp wins, then higher TxID as tiebreaker).
 * Returns null for empty array.
 */
export function latestVersion(nodes: Node[]): Node | null {
  if (nodes.length === 0) return null

  let best = nodes[0]
  for (let i = 1; i < nodes.length; i++) {
    const n = nodes[i]
    if (n.blockHeight > best.blockHeight) {
      best = n
    } else if (n.blockHeight === best.blockHeight) {
      if (n.timestamp > best.timestamp) {
        best = n
      } else if (n.timestamp === best.timestamp) {
        if (compareTxIDs(n.txID, best.txID) > 0) {
          best = n
        }
      }
    }
  }

  return best
}

/**
 * Walks up the directory tree to find the effective price.
 * Checks current node, then parent, then grandparent, etc. until root.
 * Returns 0n if no price is set anywhere in the ancestry.
 */
export async function inheritPricePerKB(store: NodeStore, node: Node): Promise<bigint> {
  let current = node
  for (let depth = 0; depth <= MAX_LINK_DEPTH; depth++) {
    if (current.pricePerKB > 0n) {
      return current.pricePerKB
    }

    // No parent means root; stop
    if (current.parent.length === 0) {
      return 0n
    }

    const parent = await store.getNodeByPubKey(current.parent)
    if (parent === null) {
      return 0n
    }

    current = parent
  }

  throw new MetanetError(
    `${ErrLinkDepthExceeded.message}: price inheritance exceeded max depth`,
    ErrLinkDepthExceeded.code,
  )
}

/**
 * Compares two TxIDs lexicographically.
 * Returns -1 if a < b, 0 if a == b, 1 if a > b.
 */
function compareTxIDs(a: Uint8Array, b: Uint8Array): number {
  const minLen = Math.min(a.length, b.length)
  for (let i = 0; i < minLen; i++) {
    if (a[i] < b[i]) return -1
    if (a[i] > b[i]) return 1
  }
  if (a.length < b.length) return -1
  if (a.length > b.length) return 1
  return 0
}
