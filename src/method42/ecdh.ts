import { PrivateKey, PublicKey } from '@bsv/sdk'
import { ErrNilPrivateKey, ErrNilPublicKey, Method42Error } from './errors.js'

/**
 * ECDH computes the shared secret between a private key and a public key
 * on the secp256k1 curve.
 *
 * Returns the x-coordinate of the shared point as 32 bytes (big-endian, zero-padded).
 * Mathematical operation: shared_point = privateKey.D * publicKey.Point
 */
export function ecdh(privateKey: PrivateKey | null, publicKey: PublicKey | null): Uint8Array {
  if (!privateKey) throw ErrNilPrivateKey()
  if (!publicKey) throw ErrNilPublicKey()

  // Use the @bsv/sdk's deriveSharedSecret: shared_point = D * P
  const sharedPoint = privateKey.deriveSharedSecret(publicKey)

  // Serialize x-coordinate as 32 bytes (zero-padded big-endian)
  const xBN = sharedPoint.getX()
  const xArray = xBN.toArray('be', 32)
  const sharedX = new Uint8Array(xArray)

  // S-07: Check for point at infinity (all-zero x-coordinate)
  if (sharedX.every(b => b === 0)) {
    throw new Method42Error('ECDH produced point at infinity', 'ERR_ECDH_FAILURE')
  }

  // Zero the intermediate array
  xArray.fill(0)

  return sharedX
}
