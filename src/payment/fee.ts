import { DEFAULT_HTLC_FEE_RATE } from './types.js'

/** Returns ceil(txSizeBytes * satPerKB / 1000). */
export function estimateFeeByKB(txSizeBytes: number, satPerKB: number): bigint {
  const rate = satPerKB > 0 ? satPerKB : DEFAULT_HTLC_FEE_RATE
  return (BigInt(txSizeBytes) * BigInt(rate) + 999n) / 1000n
}
