import { PrivateKey, PublicKey } from '@bsv/sdk'
import { ErrNilPrivateKey, ErrNilPublicKey } from './errors.js'

/**
 * ECDH computes the shared secret between a private key and a public key
 * on the secp256k1 curve.
 *
 * Returns the x-coordinate of the shared point as 32 bytes (big-endian, zero-padded).
 * Mathematical operation: shared_point = privateKey.D * publicKey.Point
 */
export function ecdh(privateKey: PrivateKey | null, publicKey: PublicKey | null): Uint8Array {
  if (!privateKey) throw ErrNilPrivateKey
  if (!publicKey) throw ErrNilPublicKey

  // Use the @bsv/sdk's deriveSharedSecret: shared_point = D * P
  const sharedPoint = privateKey.deriveSharedSecret(publicKey)

  // Serialize x-coordinate as 32 bytes (zero-padded big-endian)
  const xBN = sharedPoint.getX()
  const xArray = xBN.toArray('be', 32)
  return new Uint8Array(xArray)
}
