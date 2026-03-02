import { BitfsError } from '../errors.js'

export class Method42Error extends BitfsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'Method42Error'
  }
}

export const ErrNilPrivateKey = new Method42Error('private key is nil', 'ERR_NIL_PRIVATE_KEY')
export const ErrNilPublicKey = new Method42Error('public key is nil', 'ERR_NIL_PUBLIC_KEY')
export const ErrInvalidCiphertext = new Method42Error('invalid ciphertext', 'ERR_INVALID_CIPHERTEXT')
export const ErrDecryptionFailed = new Method42Error('decryption failed', 'ERR_DECRYPTION_FAILED')
export const ErrKeyHashMismatch = new Method42Error('key hash mismatch after decryption', 'ERR_KEY_HASH_MISMATCH')
export const ErrInvalidAccess = new Method42Error('invalid access mode', 'ERR_INVALID_ACCESS')
export const ErrHKDFFailure = new Method42Error('HKDF key derivation failed', 'ERR_HKDF_FAILURE')
