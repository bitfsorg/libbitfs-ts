import { PrivateKey } from '@bsv/sdk'
import { ErrNilPrivateKey, ErrInvalidAccess } from './errors.js'

/** Access represents the three access control modes for encrypted content. */
export const enum Access {
  /** Only the owner can decrypt (ECDH with BIP32 D_node). */
  Private = 0,
  /** Anyone can decrypt. Uses D_node = scalar 1. */
  Free = 1,
  /** Buyer decrypts via HTLC-obtained capsule. */
  Paid = 2,
}

/** Returns the string representation of an Access mode. */
export function accessToString(a: Access): string {
  switch (a) {
    case Access.Private: return 'PRIVATE'
    case Access.Free: return 'FREE'
    case Access.Paid: return 'PAID'
    default: return 'UNKNOWN'
  }
}

/**
 * Returns a PrivateKey with scalar value 1 for FREE access mode.
 * When D_node = 1: shared_point = 1 * P_node = P_node.
 * Since P_node is public, anyone can compute the encryption key.
 */
export function freePrivateKey(): PrivateKey {
  return new PrivateKey(1)
}

/**
 * Returns the effective private key for the given access mode.
 * For AccessFree, returns FreePrivateKey() (scalar 1).
 * For AccessPrivate and AccessPaid, returns the provided nodePrivateKey.
 */
export function effectivePrivateKey(access: Access, nodePrivateKey: PrivateKey | null): PrivateKey {
  switch (access) {
    case Access.Free:
      return freePrivateKey()
    case Access.Private:
    case Access.Paid:
      if (!nodePrivateKey) throw ErrNilPrivateKey
      return nodePrivateKey
    default:
      throw ErrInvalidAccess
  }
}
