import type { Store } from './types.js'
import { KEY_HASH_SIZE } from './types.js'
import { ErrNotFound, ErrInvalidKeyHash, ErrEmptyContent, StorageError } from './errors.js'
import { toHex, hexToBytes } from '../util.js'

/**
 * Validates that a key hash is exactly 32 bytes.
 */
function validateKeyHash(keyHash: Uint8Array | null | undefined): void {
  if (!keyHash || keyHash.length !== KEY_HASH_SIZE) {
    throw new StorageError(
      `storage: key hash must be 32 bytes: got ${keyHash?.length ?? 0} bytes`,
      'ERR_INVALID_KEY_HASH'
    )
  }
}

/**
 * MemoryStore implements Store using an in-memory Map.
 * Useful for testing and ephemeral storage.
 */
export class MemoryStore implements Store {
  private data = new Map<string, Uint8Array>()

  async put(keyHash: Uint8Array, ciphertext: Uint8Array): Promise<void> {
    validateKeyHash(keyHash)
    if (!ciphertext || ciphertext.length === 0) {
      throw ErrEmptyContent()
    }
    const key = toHex(keyHash)
    // Store a copy to prevent external mutation.
    this.data.set(key, new Uint8Array(ciphertext))
  }

  async get(keyHash: Uint8Array): Promise<Uint8Array> {
    validateKeyHash(keyHash)
    const key = toHex(keyHash)
    const value = this.data.get(key)
    if (!value) {
      throw ErrNotFound()
    }
    // Return a copy.
    return new Uint8Array(value)
  }

  async has(keyHash: Uint8Array): Promise<boolean> {
    validateKeyHash(keyHash)
    return this.data.has(toHex(keyHash))
  }

  async delete(keyHash: Uint8Array): Promise<void> {
    validateKeyHash(keyHash)
    const key = toHex(keyHash)
    if (!this.data.has(key)) {
      throw ErrNotFound()
    }
    this.data.delete(key)
  }

  async size(keyHash: Uint8Array): Promise<number> {
    validateKeyHash(keyHash)
    const key = toHex(keyHash)
    const value = this.data.get(key)
    if (!value) {
      throw ErrNotFound()
    }
    return value.length
  }

  async list(): Promise<Uint8Array[]> {
    const result: Uint8Array[] = []
    for (const key of this.data.keys()) {
      result.push(hexToBytes(key))
    }
    return result
  }
}
