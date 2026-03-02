import { describe, it, expect, beforeEach } from 'vitest'
import { Hash } from '@bsv/sdk'
import { tmpdir } from 'node:os'
import { mkdtemp, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { MemoryStore } from '../memory.js'
import { FileStore, keyHashToPath } from '../filestore.js'
import { ErrNotFound, ErrInvalidKeyHash, ErrEmptyContent, ErrInvalidBaseDir } from '../errors.js'

// --- Helper functions ---

/** Creates a deterministic 32-byte key hash from a seed byte. */
function makeKeyHash(seed: number): Uint8Array {
  const data = new Uint8Array([seed])
  const first = Hash.sha256(data)
  const second = Hash.sha256(first)
  return second
}

function toHex(data: Uint8Array): string {
  let hex = ''
  for (let i = 0; i < data.length; i++) {
    hex += data[i].toString(16).padStart(2, '0')
  }
  return hex
}

// =============================================================================
// MemoryStore tests
// =============================================================================

describe('MemoryStore', () => {
  let store: MemoryStore

  beforeEach(() => {
    store = new MemoryStore()
  })

  describe('put', () => {
    it('stores content successfully', async () => {
      const keyHash = makeKeyHash(0x01)
      await store.put(keyHash, new Uint8Array([1, 2, 3]))
    })

    it('rejects invalid key hash (too short)', async () => {
      await expect(store.put(new Uint8Array(16), new Uint8Array([1]))).rejects.toThrow('key hash must be 32 bytes')
    })

    it('rejects empty content', async () => {
      const keyHash = makeKeyHash(0x01)
      await expect(store.put(keyHash, new Uint8Array(0))).rejects.toThrow(ErrEmptyContent())
    })

    it('rejects null key hash', async () => {
      await expect(store.put(null as unknown as Uint8Array, new Uint8Array([1]))).rejects.toThrow('key hash must be 32 bytes')
    })
  })

  describe('get', () => {
    it('retrieves stored content', async () => {
      const keyHash = makeKeyHash(0x01)
      const data = new TextEncoder().encode('encrypted file content')
      await store.put(keyHash, data)

      const got = await store.get(keyHash)
      expect(got).toEqual(data)
    })

    it('returns a copy (not the same reference)', async () => {
      const keyHash = makeKeyHash(0x01)
      const data = new Uint8Array([1, 2, 3])
      await store.put(keyHash, data)

      const got = await store.get(keyHash)
      expect(got).toEqual(data)
      expect(got).not.toBe(data)
    })

    it('throws ErrNotFound for missing key', async () => {
      const keyHash = makeKeyHash(0xFF)
      await expect(store.get(keyHash)).rejects.toThrow(ErrNotFound())
    })

    it('rejects invalid key hash', async () => {
      await expect(store.get(new Uint8Array(1))).rejects.toThrow('key hash must be 32 bytes')
    })
  })

  describe('has', () => {
    it('returns true for existing key', async () => {
      const keyHash = makeKeyHash(0x01)
      await store.put(keyHash, new Uint8Array([1]))
      expect(await store.has(keyHash)).toBe(true)
    })

    it('returns false for missing key', async () => {
      const keyHash = makeKeyHash(0xFF)
      expect(await store.has(keyHash)).toBe(false)
    })
  })

  describe('delete', () => {
    it('deletes existing content', async () => {
      const keyHash = makeKeyHash(0x01)
      await store.put(keyHash, new Uint8Array([1]))
      await store.delete(keyHash)
      expect(await store.has(keyHash)).toBe(false)
    })

    it('throws ErrNotFound for missing key', async () => {
      const keyHash = makeKeyHash(0xFF)
      await expect(store.delete(keyHash)).rejects.toThrow(ErrNotFound())
    })

    it('double delete throws ErrNotFound', async () => {
      const keyHash = makeKeyHash(0x01)
      await store.put(keyHash, new Uint8Array([1]))
      await store.delete(keyHash)
      await expect(store.delete(keyHash)).rejects.toThrow(ErrNotFound())
    })
  })

  describe('size', () => {
    it('returns content size', async () => {
      const keyHash = makeKeyHash(0x01)
      const data = new TextEncoder().encode('some encrypted data here')
      await store.put(keyHash, data)
      expect(await store.size(keyHash)).toBe(data.length)
    })

    it('throws ErrNotFound for missing key', async () => {
      const keyHash = makeKeyHash(0xFF)
      await expect(store.size(keyHash)).rejects.toThrow(ErrNotFound())
    })
  })

  describe('list', () => {
    it('returns empty for new store', async () => {
      const keys = await store.list()
      expect(keys).toHaveLength(0)
    })

    it('returns all stored keys', async () => {
      const k1 = makeKeyHash(0x01)
      const k2 = makeKeyHash(0x02)
      const k3 = makeKeyHash(0x03)

      await store.put(k1, new Uint8Array([1]))
      await store.put(k2, new Uint8Array([2]))
      await store.put(k3, new Uint8Array([3]))

      const keys = await store.list()
      expect(keys).toHaveLength(3)

      const found = new Set(keys.map(k => toHex(k)))
      expect(found.has(toHex(k1))).toBe(true)
      expect(found.has(toHex(k2))).toBe(true)
      expect(found.has(toHex(k3))).toBe(true)
    })

    it('reflects deletion', async () => {
      const k1 = makeKeyHash(0x01)
      const k2 = makeKeyHash(0x02)

      await store.put(k1, new Uint8Array([1]))
      await store.put(k2, new Uint8Array([2]))
      await store.delete(k1)

      const keys = await store.list()
      expect(keys).toHaveLength(1)
      expect(toHex(keys[0])).toBe(toHex(k2))
    })
  })

  describe('overwrite', () => {
    it('overwrites existing content', async () => {
      const keyHash = makeKeyHash(0x01)
      await store.put(keyHash, new TextEncoder().encode('original'))
      await store.put(keyHash, new TextEncoder().encode('overwritten'))
      const data = await store.get(keyHash)
      expect(new TextDecoder().decode(data)).toBe('overwritten')
    })
  })
})

// =============================================================================
// FileStore tests
// =============================================================================

describe('FileStore', () => {
  async function createTempStore(): Promise<FileStore> {
    const dir = await mkdtemp(join(tmpdir(), 'bitfs-store-test-'))
    return FileStore.create(dir)
  }

  describe('create', () => {
    it('creates a new FileStore', async () => {
      const store = await createTempStore()
      expect(store).toBeDefined()
    })

    it('creates nested directories', async () => {
      const base = await mkdtemp(join(tmpdir(), 'bitfs-store-test-'))
      const dir = join(base, 'nested', 'store')
      const store = await FileStore.create(dir)
      expect(store).toBeDefined()

      const info = await stat(dir)
      expect(info.isDirectory()).toBe(true)
    })

    it('rejects empty base dir', async () => {
      await expect(FileStore.create('')).rejects.toThrow(ErrInvalidBaseDir())
    })
  })

  describe('keyHashToPath', () => {
    it('builds correct shard path', () => {
      const keyHash = makeKeyHash(0x42)
      const hexHash = toHex(keyHash)
      const shard = hexHash.slice(0, 2)

      const path = keyHashToPath('/base', keyHash)
      expect(path).toBe(join('/base', shard, hexHash))
    })

    it('returns empty for null/empty input', () => {
      expect(keyHashToPath('/base', new Uint8Array(0))).toBe('')
      expect(keyHashToPath('/base', null as unknown as Uint8Array)).toBe('')
    })

    it('handles all-zeros key hash', () => {
      const keyHash = new Uint8Array(32) // all zeros
      const hexHash = toHex(keyHash)
      const path = keyHashToPath('/base', keyHash)
      expect(path).toBe(join('/base', '00', hexHash))
    })

    it('handles all-FF key hash', () => {
      const keyHash = new Uint8Array(32).fill(0xFF)
      const hexHash = toHex(keyHash)
      const path = keyHashToPath('/base', keyHash)
      expect(path).toBe(join('/base', 'ff', hexHash))
    })
  })

  describe('put/get', () => {
    it('stores and retrieves content', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0x01)
      const data = new TextEncoder().encode('encrypted content')

      await store.put(keyHash, data)
      const got = await store.get(keyHash)
      expect(got).toEqual(data)
    })

    it('rejects invalid key hash', async () => {
      const store = await createTempStore()
      await expect(store.put(new Uint8Array(16), new Uint8Array([1]))).rejects.toThrow('key hash must be 32 bytes')
    })

    it('rejects empty content', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0x01)
      await expect(store.put(keyHash, new Uint8Array(0))).rejects.toThrow(ErrEmptyContent())
    })

    it('overwrites existing content', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0x01)

      await store.put(keyHash, new TextEncoder().encode('original'))
      await store.put(keyHash, new TextEncoder().encode('overwritten'))

      const data = await store.get(keyHash)
      expect(new TextDecoder().decode(data)).toBe('overwritten')
    })

    it('handles large content (1MB)', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0x42)
      const data = new Uint8Array(1024 * 1024).fill(0xFF)

      await store.put(keyHash, data)
      const got = await store.get(keyHash)
      expect(got).toEqual(data)
    })

    it('handles binary content with all byte values', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0x01)
      const data = new Uint8Array(256)
      for (let i = 0; i < 256; i++) data[i] = i

      await store.put(keyHash, data)
      const got = await store.get(keyHash)
      expect(got).toEqual(data)
    })
  })

  describe('get errors', () => {
    it('throws ErrNotFound for missing key', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0xFF)
      await expect(store.get(keyHash)).rejects.toThrow(ErrNotFound())
    })

    it('rejects invalid key hash', async () => {
      const store = await createTempStore()
      await expect(store.get(new Uint8Array(1))).rejects.toThrow('key hash must be 32 bytes')
    })

    it('rejects null key hash', async () => {
      const store = await createTempStore()
      await expect(store.get(null as unknown as Uint8Array)).rejects.toThrow('key hash must be 32 bytes')
    })
  })

  describe('has', () => {
    it('returns true for existing key', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0x01)
      await store.put(keyHash, new Uint8Array([1]))
      expect(await store.has(keyHash)).toBe(true)
    })

    it('returns false for missing key', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0xFF)
      expect(await store.has(keyHash)).toBe(false)
    })

    it('rejects invalid key hash', async () => {
      const store = await createTempStore()
      await expect(store.has(new Uint8Array(1))).rejects.toThrow('key hash must be 32 bytes')
    })
  })

  describe('delete', () => {
    it('deletes existing content', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0x01)
      await store.put(keyHash, new Uint8Array([1]))
      await store.delete(keyHash)
      expect(await store.has(keyHash)).toBe(false)
    })

    it('throws ErrNotFound for missing key', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0xFF)
      await expect(store.delete(keyHash)).rejects.toThrow(ErrNotFound())
    })

    it('double delete throws ErrNotFound', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0x01)
      await store.put(keyHash, new Uint8Array([1]))
      await store.delete(keyHash)
      await expect(store.delete(keyHash)).rejects.toThrow(ErrNotFound())
    })

    it('get after delete throws ErrNotFound', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0x01)
      await store.put(keyHash, new Uint8Array([1]))
      await store.delete(keyHash)
      await expect(store.get(keyHash)).rejects.toThrow(ErrNotFound())
    })
  })

  describe('size', () => {
    it('returns content size', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0x01)
      const data = new TextEncoder().encode('some encrypted data here')
      await store.put(keyHash, data)
      expect(await store.size(keyHash)).toBe(data.length)
    })

    it('throws ErrNotFound for missing key', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0xFF)
      await expect(store.size(keyHash)).rejects.toThrow(ErrNotFound())
    })

    it('reflects overwrite', async () => {
      const store = await createTempStore()
      const keyHash = makeKeyHash(0x01)

      await store.put(keyHash, new TextEncoder().encode('short'))
      expect(await store.size(keyHash)).toBe(5)

      await store.put(keyHash, new TextEncoder().encode('much longer content here'))
      expect(await store.size(keyHash)).toBe(24)
    })
  })

  describe('list', () => {
    it('returns empty for new store', async () => {
      const store = await createTempStore()
      const keys = await store.list()
      expect(keys).toHaveLength(0)
    })

    it('returns all stored keys', async () => {
      const store = await createTempStore()
      const k1 = makeKeyHash(0x01)
      const k2 = makeKeyHash(0x02)
      const k3 = makeKeyHash(0x03)

      await store.put(k1, new Uint8Array([1]))
      await store.put(k2, new Uint8Array([2]))
      await store.put(k3, new Uint8Array([3]))

      const keys = await store.list()
      expect(keys).toHaveLength(3)

      const found = new Set(keys.map(k => toHex(k)))
      expect(found.has(toHex(k1))).toBe(true)
      expect(found.has(toHex(k2))).toBe(true)
      expect(found.has(toHex(k3))).toBe(true)
    })

    it('reflects deletion', async () => {
      const store = await createTempStore()
      const k1 = makeKeyHash(0x01)
      const k2 = makeKeyHash(0x02)

      await store.put(k1, new Uint8Array([1]))
      await store.put(k2, new Uint8Array([2]))
      await store.delete(k1)

      const keys = await store.list()
      expect(keys).toHaveLength(1)
      expect(toHex(keys[0])).toBe(toHex(k2))
    })

    it('handles multiple shard directories', async () => {
      const store = await createTempStore()
      for (let i = 0; i < 20; i++) {
        const keyHash = makeKeyHash(i)
        await store.put(keyHash, new Uint8Array([i + 1]))
      }

      const keys = await store.list()
      expect(keys).toHaveLength(20)
    })
  })

  describe('shard directory structure', () => {
    it('creates shard subdirectory on put', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'bitfs-store-test-'))
      const store = await FileStore.create(dir)

      const keyHash = makeKeyHash(0x01)
      await store.put(keyHash, new Uint8Array([1]))

      const hexHash = toHex(keyHash)
      const shardDir = join(dir, hexHash.slice(0, 2))
      const info = await stat(shardDir)
      expect(info.isDirectory()).toBe(true)

      // Verify file exists within shard.
      const filePath = join(shardDir, hexHash)
      const fileInfo = await stat(filePath)
      expect(fileInfo.isFile()).toBe(true)
    })
  })
})
