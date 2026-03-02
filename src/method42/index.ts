// method42 — Method 42 ECDH encryption engine for BitFS

// Errors
export {
  Method42Error,
  ErrNilPrivateKey,
  ErrNilPublicKey,
  ErrInvalidCiphertext,
  ErrDecryptionFailed,
  ErrKeyHashMismatch,
  ErrInvalidAccess,
  ErrHKDFFailure,
} from './errors.js'

// Access modes
export { Access, accessToString, freePrivateKey, effectivePrivateKey } from './access.js'

// ECDH
export { ecdh } from './ecdh.js'

// Key derivation
export {
  HKDF_INFO,
  HKDF_BUYER_MASK_INFO,
  HKDF_METADATA_INFO,
  AES_KEY_LEN,
  METADATA_SALT_LEN,
  HASH_SIZE,
  computeKeyHash,
  deriveAESKey,
  deriveMetadataKey,
  deriveMetadataKeyWithSalt,
  deriveBuyerMask,
  deriveBuyerMaskWithNonce,
} from './kdf.js'

// Encryption / decryption
export {
  NONCE_LEN,
  GCM_TAG_LEN,
  MIN_CIPHERTEXT_LEN,
  MIN_ENC_PAYLOAD_LEN,
  encrypt,
  decrypt,
  reEncrypt,
  encryptMetadata,
  decryptMetadata,
} from './encrypt.js'
export type { EncryptResult, DecryptResult } from './encrypt.js'

// Capsule (paid content flow)
export {
  computeCapsule,
  computeCapsuleWithNonce,
  computeCapsuleHash,
  decryptWithCapsule,
  decryptWithCapsuleNonce,
} from './capsule.js'

// Rabin signature scheme
export {
  generateRabinKey,
  rabinSign,
  rabinVerify,
  serializeRabinSignature,
  deserializeRabinSignature,
  serializeRabinPubKey,
  deserializeRabinPubKey,
} from './rabin.js'
export type { RabinKeyPair } from './rabin.js'
