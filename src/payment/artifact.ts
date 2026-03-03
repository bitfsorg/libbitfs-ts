import { hexToBytes, toHex } from '../util.js'
import {
  INVOICE_ID_LEN,
  CAPSULE_HASH_LEN,
  PUB_KEY_HASH_LEN,
} from './types.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Represents a compiled sCrypt contract artifact. */
export interface Artifact {
  version: number
  contract: string
  hex: string
  abi: ABIEntity[]
  md5: string
}

/** Describes a constructor or public function in the contract ABI. */
export interface ABIEntity {
  name?: string
  type: 'constructor' | 'function'
  params: { name: string; type: string }[]
  index?: number
}

// ---------------------------------------------------------------------------
// Embedded artifact (mirrors Go's go:embed)
// ---------------------------------------------------------------------------

/**
 * The compiled BitfsHTLC sCrypt artifact, embedded at build time.
 * Hex contains constructor parameter placeholders:
 *   <invoiceId>, <capsuleHash>, <sellerPkh>, <buyerPkh>, <timeout>
 *
 * Source: contracts/artifacts/bitfsHTLC.json
 * To update: recompile the sCrypt contract and copy the new JSON here.
 */
const HTLC_ARTIFACT: Artifact = {
  version: 9,
  contract: 'BitfsHTLC',
  md5: 'b408d00934d0f2a46e26737b3c2f645b',
  abi: [
    {
      type: 'function',
      name: 'claim',
      index: 0,
      params: [
        { name: 'preimage', type: 'bytes' },
        { name: 'sig', type: 'Sig' },
        { name: 'pubkey', type: 'PubKey' },
      ],
    },
    {
      type: 'function',
      name: 'refund',
      index: 1,
      params: [
        { name: 'sig', type: 'Sig' },
        { name: 'pubkey', type: 'PubKey' },
        { name: '__scrypt_ts_txPreimage', type: 'SigHashPreimage' },
      ],
    },
    {
      type: 'constructor',
      params: [
        { name: 'invoiceId', type: 'bytes' },
        { name: 'capsuleHash', type: 'Sha256' },
        { name: 'sellerPkh', type: 'Ripemd160' },
        { name: 'buyerPkh', type: 'Ripemd160' },
        { name: 'timeout', type: 'int' },
      ],
    },
  ],
  hex: '2097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c00000000000000<invoiceId><capsuleHash><sellerPkh><buyerPkh><timeout>54795c7a755b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a53795b7a755a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a52795a7a75597a597a597a597a597a597a597a597a597a78597a75587a587a587a587a587a587a587a587a76587a75577a577a577a577a577a577a577a6d6d755a790087635d79a85679885b79a95579885c795c79ac6b6d6d6d6d6d6d6d6c675a795187635b790141785c795c79210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce08105e7956795679aa7676517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e817757795679567956795679537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e6e9776009f636e936776687777777b757c6e5296a0636e7c947b757c6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f77545379935279930130787e527e54797e58797e527e53797e52797e57797e6b6d6d6d6d6d6d6c765779ac6b6d6d6d6d6d6c77695b79767682776e54947f757858947f7777777601007e8177777b757c5b79767682776e0128947f7578012c947f7777777601007e81777777527951527905ffffffff009f7778040065cd1d9f6376635379040065cd1d9f6700687768766353795279a26700687777695c79a95479885d795d79ac6b6d6d6d6d6d6d6d6c67006868',
}

// ---------------------------------------------------------------------------
// Artifact access
// ---------------------------------------------------------------------------

/** Returns the embedded BitfsHTLC artifact. */
export function loadArtifact(): Artifact {
  return HTLC_ARTIFACT
}

// ---------------------------------------------------------------------------
// Script instantiation
// ---------------------------------------------------------------------------

/**
 * Substitutes constructor parameters into the hex template and returns the
 * locking script bytes. Parameter placeholders in the compiled sCrypt hex:
 *
 *   <invoiceId>   -- 16-byte invoice ID (hex-encoded to 32 chars)
 *   <capsuleHash> -- 32-byte SHA256 capsule hash (hex-encoded to 64 chars)
 *   <sellerPkh>   -- 20-byte seller pubkey hash (hex-encoded to 40 chars)
 *   <buyerPkh>    -- 20-byte buyer pubkey hash (hex-encoded to 40 chars)
 *   <timeout>     -- sCrypt integer (little-endian signed magnitude encoding)
 */
export function instantiateHTLC(
  invoiceId: Uint8Array,    // 16 bytes
  capsuleHash: Uint8Array,  // 32 bytes
  sellerPkh: Uint8Array,    // 20 bytes
  buyerPkh: Uint8Array,     // 20 bytes
  timeout: number,
): Uint8Array {
  if (invoiceId.length !== INVOICE_ID_LEN) {
    throw new Error(`invoiceId must be ${INVOICE_ID_LEN} bytes, got ${invoiceId.length}`)
  }
  if (capsuleHash.length !== CAPSULE_HASH_LEN) {
    throw new Error(`capsuleHash must be ${CAPSULE_HASH_LEN} bytes, got ${capsuleHash.length}`)
  }
  if (sellerPkh.length !== PUB_KEY_HASH_LEN) {
    throw new Error(`sellerPkh must be ${PUB_KEY_HASH_LEN} bytes, got ${sellerPkh.length}`)
  }
  if (buyerPkh.length !== PUB_KEY_HASH_LEN) {
    throw new Error(`buyerPkh must be ${PUB_KEY_HASH_LEN} bytes, got ${buyerPkh.length}`)
  }

  let hex = HTLC_ARTIFACT.hex
  hex = hex.replace('<invoiceId>', toHex(invoiceId))
  hex = hex.replace('<capsuleHash>', toHex(capsuleHash))
  hex = hex.replace('<sellerPkh>', toHex(sellerPkh))
  hex = hex.replace('<buyerPkh>', toHex(buyerPkh))
  hex = hex.replace('<timeout>', encodeScryptInt(timeout))

  return hexToBytes(hex)
}

// ---------------------------------------------------------------------------
// Byte offsets for extraction
// ---------------------------------------------------------------------------

/**
 * Byte offsets of constructor parameters within the instantiated sCrypt
 * artifact script. The fixed-size prefix before the first parameter is
 * 107 bytes. All four data fields precede the variable-length timeout
 * encoding, so their offsets are constant.
 */
export const HTLC_INVOICE_ID_OFFSET = 107      // invoiceId: 16 bytes
export const HTLC_CAPSULE_HASH_OFFSET = 123     // capsuleHash: 32 bytes
export const HTLC_SELLER_PKH_OFFSET = 155       // sellerPkh: 20 bytes
export const HTLC_BUYER_PKH_OFFSET = 175        // buyerPkh: 20 bytes

/** Minimum script length: all fixed fields + at least 1-byte timeout + some suffix. */
export const HTLC_MIN_SCRIPT_LEN = HTLC_BUYER_PKH_OFFSET + PUB_KEY_HASH_LEN + 1

/**
 * The known prefix bytes of the compiled sCrypt artifact script (107 bytes).
 * Used to identify whether a script was produced by the BitfsHTLC artifact.
 */
const ARTIFACT_PREFIX: Uint8Array = hexToBytes(
  HTLC_ARTIFACT.hex.substring(0, HTLC_ARTIFACT.hex.indexOf('<')),
)

/** Returns true if the script bytes start with the known sCrypt artifact prefix. */
export function isArtifactScript(scriptBytes: Uint8Array): boolean {
  if (scriptBytes.length < ARTIFACT_PREFIX.length) {
    return false
  }
  for (let i = 0; i < ARTIFACT_PREFIX.length; i++) {
    if (scriptBytes[i] !== ARTIFACT_PREFIX[i]) return false
  }
  return true
}

// ---------------------------------------------------------------------------
// sCrypt integer encoding
// ---------------------------------------------------------------------------

/**
 * Encodes an integer using sCrypt's little-endian signed magnitude format.
 * This matches Bitcoin Script's number encoding:
 *   - 0 encodes as "00"
 *   - Positive values are little-endian; if the high bit of the last byte
 *     is set, an extra 0x00 byte is appended to distinguish from negative
 *   - Negative values set the high bit of the last byte as the sign bit
 */
export function encodeScryptInt(v: number): string {
  if (v === 0) return '00'
  const negative = v < 0
  if (negative) v = -v
  const buf: number[] = []
  while (v > 0) {
    buf.push(v & 0xff)
    v = Math.floor(v / 256)
  }
  // If the high bit of the last byte is set, we need an extra byte
  // to hold the sign bit.
  if (buf[buf.length - 1] & 0x80) {
    buf.push(negative ? 0x80 : 0x00)
  } else if (negative) {
    buf[buf.length - 1] |= 0x80
  }
  return buf.map(b => b.toString(16).padStart(2, '0')).join('')
}
