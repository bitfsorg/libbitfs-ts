import { Hash } from '@bsv/sdk'
import type { Store } from './types.js'
import { KEY_HASH_SIZE } from './types.js'
import { ErrNotFound, ErrInvalidKeyHash, StorageError } from './errors.js'
import { timingSafeEqual, toHex } from '../util.js'

/** MaxContentResponseSize is the maximum allowed response body size (1 GB). */
export const MAX_CONTENT_RESPONSE_SIZE = 1 << 30

/**
 * ContentResolver fetches encrypted content by key_hash from multiple sources
 * in priority order: local Store -> daemon HTTP endpoints.
 * It returns ciphertext only; the caller is responsible for decryption.
 */
export class ContentResolver {
  store: Store | null
  endpoints: string[]

  constructor(store: Store | null, endpoints: string[] = []) {
    this.store = store
    this.endpoints = endpoints
  }

  /**
   * Fetch retrieves ciphertext for the given key_hash, trying sources in order:
   * 1. Local Store
   * 2. Daemon HTTP endpoints (GET {baseURL}/_bitfs/data/{hex(keyHash)})
   */
  async fetch(keyHash: Uint8Array): Promise<Uint8Array> {
    if (!keyHash || keyHash.length !== KEY_HASH_SIZE) {
      throw new StorageError(
        `storage: key hash must be 32 bytes: got ${keyHash?.length ?? 0} bytes`,
        'ERR_INVALID_KEY_HASH'
      )
    }

    // 1. Try local storage first.
    if (this.store) {
      try {
        const data = await this.store.get(keyHash)
        return data
      } catch (err) {
        if (!(err instanceof StorageError && err.code === 'ERR_NOT_FOUND')) {
          throw new Error(`resolver: local store: ${(err as Error).message}`)
        }
        // Not found locally — fall through to endpoints.
      }
    }

    // 2. Try daemon HTTP endpoints.
    const hashHex = toHex(keyHash)

    for (const ep of this.endpoints) {
      try {
        const data = await this.fetchFromEndpoint(ep, hashHex)

        // Verify content hash before trusting remote data.
        const actualHash = new Uint8Array(Hash.sha256(data))
        if (!timingSafeEqual(actualHash, keyHash)) {
          // Hash mismatch — skip this endpoint.
          continue
        }

        // Cache locally for future access.
        if (this.store) {
          try { await this.store.put(keyHash, data) } catch { /* best-effort */ }
        }

        return data
      } catch {
        // Continue to next endpoint on any error.
        continue
      }
    }

    throw new StorageError(
      `resolver: storage: content not found: key_hash ${hashHex}`,
      'ERR_NOT_FOUND'
    )
  }

  private async fetchFromEndpoint(baseURL: string, hashHex: string): Promise<Uint8Array> {
    const url = `${baseURL}/_bitfs/data/${hashHex}`
    const resp = await fetch(url, { signal: AbortSignal.timeout(30_000) })

    if (!resp.ok) {
      throw new Error(`resolver: endpoint ${baseURL}: HTTP ${resp.status}`)
    }

    const buffer = await resp.arrayBuffer()
    if (buffer.byteLength === 0) {
      throw new Error(`resolver: endpoint ${baseURL}: empty response`)
    }
    if (buffer.byteLength > MAX_CONTENT_RESPONSE_SIZE) {
      throw new Error(`resolver: endpoint ${baseURL}: response too large`)
    }

    return new Uint8Array(buffer)
  }
}

