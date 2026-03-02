/** KeyHashSize is the required length of a key hash (SHA256 output = 32 bytes). */
export const KEY_HASH_SIZE = 32

/**
 * Store provides content-addressed storage for encrypted file data.
 * Keys are SHA256(SHA256(plaintext)) hashes (32 bytes), values are opaque ciphertext.
 */
export interface Store {
  /** Put stores encrypted content indexed by key_hash. */
  put(keyHash: Uint8Array, ciphertext: Uint8Array): Promise<void>

  /** Get retrieves encrypted content by key_hash. */
  get(keyHash: Uint8Array): Promise<Uint8Array>

  /** Has checks if content exists for the given key_hash. */
  has(keyHash: Uint8Array): Promise<boolean>

  /** Delete removes content by key_hash. */
  delete(keyHash: Uint8Array): Promise<void>

  /** Size returns the size in bytes of stored content for key_hash. */
  size(keyHash: Uint8Array): Promise<number>

  /** List returns all stored key hashes (for backup/export). */
  list(): Promise<Uint8Array[]>
}
