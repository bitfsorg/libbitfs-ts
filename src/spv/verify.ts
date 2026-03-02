// spv/verify — Full SPV transaction verification

import { HASH_SIZE } from './types.js'
import type { StoredTx, HeaderStore } from './types.js'
import { Network } from './types.js'
import { SpvError } from './errors.js'
import { verifyPoW, validateMinDifficulty } from './header.js'
import { doubleHash, verifyMerkleProof } from './merkle.js'

/**
 * Performs the full SPV verification chain:
 *  1. Transaction integrity: TxID is valid (32 bytes)
 *  2. RawTx integrity: DoubleHash(rawTx) must match TxID (if rawTx present)
 *  3. Merkle proof: tx is included in a block
 *  4. Block header: exists in the header store with valid PoW
 *  5. Merkle root: proof matches the header's merkleRoot
 *
 * Throws SpvError on verification failure.
 */
export async function verifyTransaction(tx: StoredTx, headers: HeaderStore): Promise<void> {
  // Step 1: Transaction integrity -- TxID must be valid
  if (tx.txID.length !== HASH_SIZE) {
    throw new SpvError(`spv: TxID must be ${HASH_SIZE} bytes`, 'ERR_INVALID_TX_ID')
  }

  // Verify RawTx integrity: DoubleHash(RawTx) must match TxID.
  if (tx.rawTx.length > 0) {
    const computed = doubleHash(tx.rawTx)
    if (!bytesEqual(computed, tx.txID)) {
      throw new SpvError('spv: RawTx hash does not match TxID', 'ERR_INVALID_TX_ID')
    }
  }

  // Step 2: Must have a Merkle proof (confirmed transaction)
  if (!tx.merkleProof) {
    throw new SpvError('spv: transaction is unconfirmed', 'ERR_UNCONFIRMED')
  }

  // Verify proof TxID matches stored TxID
  if (!bytesEqual(tx.txID, tx.merkleProof.txID)) {
    throw new SpvError(
      'spv: stored TxID does not match proof TxID',
      'ERR_MERKLE_PROOF_INVALID',
    )
  }

  // Step 3: Look up the block header
  if (tx.merkleProof.blockHash.length !== HASH_SIZE) {
    throw new SpvError(
      `spv: proof block hash must be ${HASH_SIZE} bytes`,
      'ERR_INVALID_HEADER',
    )
  }

  const header = await headers.getHeader(tx.merkleProof.blockHash)
  if (header === null) {
    throw new SpvError('spv: header not found', 'ERR_HEADER_NOT_FOUND')
  }

  // Step 3.5: Verify the header's Proof-of-Work
  verifyPoW(header)

  // Step 4: Verify the Merkle proof against the header's Merkle root
  const valid = verifyMerkleProof(tx.merkleProof, header.merkleRoot)
  if (!valid) {
    throw new SpvError('spv: merkle proof invalid', 'ERR_MERKLE_PROOF_INVALID')
  }
}

/**
 * Performs the full SPV verification chain with network-aware minimum
 * difficulty validation. Same as verifyTransaction but also checks that
 * the block header meets the minimum difficulty for the given network.
 */
export async function verifyTransactionWithNetwork(
  tx: StoredTx,
  headers: HeaderStore,
  net: Network,
): Promise<void> {
  // Step 1: Transaction integrity -- TxID must be valid
  if (tx.txID.length !== HASH_SIZE) {
    throw new SpvError(`spv: TxID must be ${HASH_SIZE} bytes`, 'ERR_INVALID_TX_ID')
  }

  // Verify RawTx integrity: DoubleHash(RawTx) must match TxID.
  if (tx.rawTx.length > 0) {
    const computed = doubleHash(tx.rawTx)
    if (!bytesEqual(computed, tx.txID)) {
      throw new SpvError('spv: RawTx hash does not match TxID', 'ERR_INVALID_TX_ID')
    }
  }

  // Step 2: Must have a Merkle proof (confirmed transaction)
  if (!tx.merkleProof) {
    throw new SpvError('spv: transaction is unconfirmed', 'ERR_UNCONFIRMED')
  }

  // Verify proof TxID matches stored TxID
  if (!bytesEqual(tx.txID, tx.merkleProof.txID)) {
    throw new SpvError(
      'spv: stored TxID does not match proof TxID',
      'ERR_MERKLE_PROOF_INVALID',
    )
  }

  // Step 3: Look up the block header
  if (tx.merkleProof.blockHash.length !== HASH_SIZE) {
    throw new SpvError(
      `spv: proof block hash must be ${HASH_SIZE} bytes`,
      'ERR_INVALID_HEADER',
    )
  }

  const header = await headers.getHeader(tx.merkleProof.blockHash)
  if (header === null) {
    throw new SpvError('spv: header not found', 'ERR_HEADER_NOT_FOUND')
  }

  // Step 3.5: Verify the header's Proof-of-Work
  verifyPoW(header)

  // Step 3.6: Verify minimum network difficulty
  validateMinDifficulty(header, net)

  // Step 4: Verify the Merkle proof against the header's Merkle root
  const valid = verifyMerkleProof(tx.merkleProof, header.merkleRoot)
  if (!valid) {
    throw new SpvError('spv: merkle proof invalid', 'ERR_MERKLE_PROOF_INVALID')
  }
}

/** Compares two Uint8Arrays for byte-level equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}
