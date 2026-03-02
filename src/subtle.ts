/**
 * Web Crypto API compatibility helpers.
 *
 * TypeScript 5.9+ made Uint8Array generic (Uint8Array<ArrayBufferLike>),
 * which is not assignable to BufferSource (requires ArrayBuffer, not
 * SharedArrayBuffer). These wrappers centralise the necessary casts.
 */

type Buf = unknown; // opaque cast target

export async function importAESKey(
  raw: Uint8Array,
  usage: KeyUsage[],
): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw as Buf as BufferSource, { name: 'AES-GCM' }, false, usage)
}

export async function aesGcmEncrypt(
  key: CryptoKey,
  plaintext: Uint8Array,
  iv: Uint8Array,
  additionalData?: Uint8Array,
): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as Buf as BufferSource, additionalData: additionalData as Buf as BufferSource },
    key,
    plaintext as Buf as BufferSource,
  )
}

export async function aesGcmDecrypt(
  key: CryptoKey,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  additionalData?: Uint8Array,
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as Buf as BufferSource, additionalData: additionalData as Buf as BufferSource },
    key,
    ciphertext as Buf as BufferSource,
  )
}
