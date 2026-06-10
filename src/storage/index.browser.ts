// storage — Content-addressed storage for BitFS (browser entry)
//
// Identical to ./index.ts EXCEPT it omits FileStore/keyHashToPath, whose
// module (./filestore.ts) statically imports node:fs/promises and node:path
// and therefore cannot be bundled for browsers. Browser consumers get this
// entry via the "browser" condition in package.json exports; Node consumers
// keep the full barrel. Keep both barrels in sync when adding exports.

// Errors
export {
  StorageError,
  ErrNotFound,
  ErrInvalidKeyHash,
  ErrStoreFull,
  ErrIOFailure,
  ErrEmptyContent,
  ErrInvalidBaseDir,
  ErrUnsupportedCompression,
  ErrRecombinationHashMismatch,
  ErrDecompressedTooLarge,
  ErrInvalidChunkSize,
} from './errors.js'

// Types
export type { Store } from './types.js'
export { KEY_HASH_SIZE } from './types.js'

// Compression
export {
  CompressNone,
  CompressLZW,
  CompressGZIP,
  CompressZSTD,
  MAX_DECOMPRESSED_SIZE,
  compress,
  decompress,
} from './compress.js'

// Chunking
export {
  DEFAULT_CHUNK_SIZE,
  splitIntoChunks,
  recombineChunks,
  computeRecombinationHash,
} from './chunk.js'

// FileStore is intentionally NOT exported here (Node.js filesystem only).
// Import it from the Node entry: `import { storage } from '@bitfs/libbitfs'`.

// MemoryStore (in-memory, browser-safe)
export { MemoryStore } from './memory.js'

// ContentResolver
export { ContentResolver, MAX_CONTENT_RESPONSE_SIZE } from './resolver.js'
