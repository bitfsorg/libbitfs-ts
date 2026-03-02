// metanet/cltv — CheckLockTimeVerify access control

import type { Node } from './types.js'
import { CLTVResult } from './types.js'

/**
 * Checks if content is accessible at the given block height.
 * Returns CLTVAllowed if:
 *   - cltvHeight is 0 (no restriction), or
 *   - currentHeight >= cltvHeight
 * Returns CLTVDenied if currentHeight < cltvHeight.
 *
 * A null-ish node returns CLTVDenied.
 */
export function checkCLTVAccess(node: Node | null | undefined, currentHeight: number): CLTVResult {
  if (node == null) {
    return CLTVResult.Denied
  }
  if (node.cltvHeight === 0) {
    return CLTVResult.Allowed
  }
  if (currentHeight >= node.cltvHeight) {
    return CLTVResult.Allowed
  }
  return CLTVResult.Denied
}
