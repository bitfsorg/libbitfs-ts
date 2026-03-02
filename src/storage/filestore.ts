import { mkdir, readFile, writeFile, unlink, stat, readdir, rename } from 'node:fs/promises'
import { join } from 'node:path'
import type { Store } from './types.js'
import { KEY_HASH_SIZE } from './types.js'
import {
  ErrNotFound,
  ErrInvalidKeyHash,
  ErrIOFailure,
  ErrEmptyContent,
  ErrInvalidBaseDir,
  StorageError,
} from './errors.js'

/**
 * Converts a key_hash to a hex string.
 */
function toHex(data: Uint8Array): string {
  let hex = ''
  for (let i = 0; i < data.length; i++) {
    hex += data[i].toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Converts a hex string to Uint8Array.
 */
function fromHex(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0) return null
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    const high = parseInt(hex[i], 16)
    const low = parseInt(hex[i + 1], 16)
    if (isNaN(high) || isNaN(low)) return null
    bytes[i / 2] = (high << 4) | low
  }
  return bytes
}

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
 * KeyHashToPath converts a key_hash to its filesystem path.
 * Uses first byte as subdirectory for sharding: {base}/{ab}/{abcdef...}
 */
export function keyHashToPath(baseDir: string, keyHash: Uint8Array): string {
  if (!keyHash || keyHash.length === 0) {
    return ''
  }
  const hexHash = toHex(keyHash)
  const shard = hexHash.slice(0, 2)
  return join(baseDir, shard, hexHash)
}

/**
 * FileStore implements Store using the local filesystem.
 * Files are stored at: {baseDir}/{hex(keyHash[:1])}/{hex(keyHash)}
 * The first byte (2 hex chars) is used as a subdirectory for sharding.
 */
export class FileStore implements Store {
  readonly baseDir: string

  private constructor(baseDir: string) {
    this.baseDir = baseDir
  }

  /**
   * Creates a new file-based content store.
   * baseDir is typically "~/.bitfs/store". The directory is created if it does not exist.
   */
  static async create(baseDir: string): Promise<FileStore> {
    if (!baseDir) {
      throw ErrInvalidBaseDir
    }
    try {
      await mkdir(baseDir, { recursive: true, mode: 0o700 })
    } catch (err) {
      throw new StorageError(
        `storage: I/O failure: ${(err as Error).message}`,
        'ERR_IO_FAILURE'
      )
    }
    return new FileStore(baseDir)
  }

  private shardDir(keyHash: Uint8Array): string {
    const hexHash = toHex(keyHash)
    return join(this.baseDir, hexHash.slice(0, 2))
  }

  private filePath(keyHash: Uint8Array): string {
    return keyHashToPath(this.baseDir, keyHash)
  }

  async put(keyHash: Uint8Array, ciphertext: Uint8Array): Promise<void> {
    validateKeyHash(keyHash)
    if (!ciphertext || ciphertext.length === 0) {
      throw ErrEmptyContent
    }

    const shard = this.shardDir(keyHash)
    try {
      await mkdir(shard, { recursive: true, mode: 0o700 })
    } catch (err) {
      throw new StorageError(
        `storage: I/O failure: ${(err as Error).message}`,
        'ERR_IO_FAILURE'
      )
    }

    const path = this.filePath(keyHash)
    const tmp = path + '.tmp'

    try {
      await writeFile(tmp, ciphertext, { mode: 0o600 })
    } catch (err) {
      throw new StorageError(
        `storage: I/O failure: ${(err as Error).message}`,
        'ERR_IO_FAILURE'
      )
    }

    try {
      await rename(tmp, path)
    } catch (err) {
      // Best-effort cleanup of temp file.
      try { await unlink(tmp) } catch { /* ignore */ }
      throw new StorageError(
        `storage: I/O failure: ${(err as Error).message}`,
        'ERR_IO_FAILURE'
      )
    }
  }

  async get(keyHash: Uint8Array): Promise<Uint8Array> {
    validateKeyHash(keyHash)

    const path = this.filePath(keyHash)
    try {
      return new Uint8Array(await readFile(path))
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        throw ErrNotFound
      }
      throw new StorageError(
        `storage: I/O failure: ${(err as Error).message}`,
        'ERR_IO_FAILURE'
      )
    }
  }

  async has(keyHash: Uint8Array): Promise<boolean> {
    validateKeyHash(keyHash)

    const path = this.filePath(keyHash)
    try {
      await stat(path)
      return true
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        return false
      }
      throw new StorageError(
        `storage: I/O failure: ${(err as Error).message}`,
        'ERR_IO_FAILURE'
      )
    }
  }

  async delete(keyHash: Uint8Array): Promise<void> {
    validateKeyHash(keyHash)

    const path = this.filePath(keyHash)
    try {
      await unlink(path)
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        throw ErrNotFound
      }
      throw new StorageError(
        `storage: I/O failure: ${(err as Error).message}`,
        'ERR_IO_FAILURE'
      )
    }
  }

  async size(keyHash: Uint8Array): Promise<number> {
    validateKeyHash(keyHash)

    const path = this.filePath(keyHash)
    try {
      const info = await stat(path)
      return info.size
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        throw ErrNotFound
      }
      throw new StorageError(
        `storage: I/O failure: ${(err as Error).message}`,
        'ERR_IO_FAILURE'
      )
    }
  }

  async list(): Promise<Uint8Array[]> {
    const result: Uint8Array[] = []

    let entryNames: string[]
    try {
      entryNames = await readdir(this.baseDir)
    } catch (err) {
      throw new StorageError(
        `storage: I/O failure: ${(err as Error).message}`,
        'ERR_IO_FAILURE'
      )
    }

    for (const name of entryNames) {
      if (name.length !== 2) continue

      const shardPath = join(this.baseDir, name)
      // Check if it's a directory.
      try {
        const info = await stat(shardPath)
        if (!info.isDirectory()) continue
      } catch {
        continue
      }

      let fileNames: string[]
      try {
        fileNames = await readdir(shardPath)
      } catch {
        continue
      }

      for (const fileName of fileNames) {
        // Check it's not a directory.
        try {
          const info = await stat(join(shardPath, fileName))
          if (info.isDirectory()) continue
        } catch {
          continue
        }
        const keyHash = fromHex(fileName)
        if (!keyHash) continue
        if (keyHash.length !== KEY_HASH_SIZE) continue
        result.push(keyHash)
      }
    }

    return result
  }
}
