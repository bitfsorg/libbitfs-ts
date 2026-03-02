import type { RevShareEntry, ShareData, Distribution } from './types.js'
import {
  ErrNoEntries,
  ErrZeroTotalShares,
  ErrShareSumMismatch,
  ErrOverflow,
  ErrShareConservationViolation,
  RevShareError,
} from './errors.js'

const MAX_U64 = (1n << 64n) - 1n

/**
 * DistributeRevenue calculates per-shareholder payouts.
 * The last entry gets the remainder to avoid integer division precision loss.
 *
 * Safety guarantees:
 *   - Validates sum(entry.share) == totalShares
 *   - Zero totalPayment returns all-zero distributions
 *   - Uses BigInt for safe 128-bit intermediate multiplication
 *   - Checks for underflow before remainder calculation
 */
export function distributeRevenue(
  totalPayment: bigint,
  entries: RevShareEntry[],
  totalShares: bigint,
): Distribution[] {
  if (entries.length === 0) {
    throw new RevShareError(ErrNoEntries.message, ErrNoEntries.code)
  }
  if (totalShares === 0n) {
    throw new RevShareError(ErrZeroTotalShares.message, ErrZeroTotalShares.code)
  }

  // Validate that sum of entry shares equals totalShares.
  let shareSum = 0n
  for (const entry of entries) {
    shareSum += entry.share
    if (shareSum > MAX_U64) {
      throw new RevShareError(
        `${ErrOverflow.message}: share sum exceeds uint64`,
        ErrOverflow.code,
      )
    }
  }
  if (shareSum !== totalShares) {
    throw new RevShareError(
      `${ErrShareSumMismatch.message}: sum ${shareSum} != totalShares ${totalShares}`,
      ErrShareSumMismatch.code,
    )
  }

  // Zero payment: return all-zero distributions.
  if (totalPayment === 0n) {
    return entries.map((entry) => ({
      address: new Uint8Array(entry.address),
      amount: 0n,
    }))
  }

  const distributions: Distribution[] = new Array(entries.length)
  let distributed = 0n

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]
    if (i === entries.length - 1) {
      // Last entry gets remainder.
      if (distributed > totalPayment) {
        throw new RevShareError(
          `${ErrOverflow.message}: distributed ${distributed} exceeds total payment ${totalPayment}`,
          ErrOverflow.code,
        )
      }
      distributions[i] = {
        address: new Uint8Array(entry.address),
        amount: totalPayment - distributed,
      }
    } else {
      // BigInt handles arbitrary-precision multiplication natively.
      const amount = (totalPayment * entry.share) / totalShares
      distributions[i] = {
        address: new Uint8Array(entry.address),
        amount,
      }
      distributed += amount
    }
  }

  return distributions
}

/**
 * ValidateShareConservation checks that total input shares equal total output shares.
 * Uses overflow-safe summation.
 */
export function validateShareConservation(
  inputs: ShareData[],
  outputs: ShareData[],
): void {
  const inputTotal = safeSum(inputs)
  const outputTotal = safeSum(outputs)
  if (inputTotal !== outputTotal) {
    throw new RevShareError(
      `${ErrShareConservationViolation.message}: input=${inputTotal} output=${outputTotal}`,
      ErrShareConservationViolation.code,
    )
  }
}

/**
 * safeSum computes the sum of ShareData amounts with overflow detection.
 */
function safeSum(items: ShareData[]): bigint {
  let total = 0n
  for (const item of items) {
    total += item.amount
    if (total > MAX_U64) {
      throw new RevShareError(
        `${ErrOverflow.message}: sum overflow at amount ${item.amount}`,
        ErrOverflow.code,
      )
    }
  }
  return total
}
