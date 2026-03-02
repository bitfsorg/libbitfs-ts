// storage — Content-addressed storage for BitFS

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

// FileStore (Node.js filesystem)
export { FileStore, keyHashToPath } from './filestore.js'

// MemoryStore (in-memory for testing)
export { MemoryStore } from './memory.js'

// ContentResolver
export { ContentResolver, MAX_CONTENT_RESPONSE_SIZE } from './resolver.js'
