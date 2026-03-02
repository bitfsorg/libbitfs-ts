import { BitfsError } from '../errors.js'

export class StorageError extends BitfsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'StorageError'
  }
}

export const ErrNotFound = new StorageError('storage: content not found', 'ERR_NOT_FOUND')
export const ErrInvalidKeyHash = new StorageError('storage: key hash must be 32 bytes', 'ERR_INVALID_KEY_HASH')
export const ErrStoreFull = new StorageError('storage: disk space exhausted', 'ERR_STORE_FULL')
export const ErrIOFailure = new StorageError('storage: I/O failure', 'ERR_IO_FAILURE')
export const ErrEmptyContent = new StorageError('storage: content is empty', 'ERR_EMPTY_CONTENT')
export const ErrInvalidBaseDir = new StorageError('storage: invalid base directory', 'ERR_INVALID_BASE_DIR')
export const ErrUnsupportedCompression = new StorageError('storage: unsupported compression scheme', 'ERR_UNSUPPORTED_COMPRESSION')
export const ErrRecombinationHashMismatch = new StorageError('storage: recombination hash mismatch', 'ERR_RECOMBINATION_HASH_MISMATCH')
export const ErrDecompressedTooLarge = new StorageError('storage: decompressed data exceeds maximum size', 'ERR_DECOMPRESSED_TOO_LARGE')
export const ErrInvalidChunkSize = new StorageError('storage: chunk size must be positive', 'ERR_INVALID_CHUNK_SIZE')
