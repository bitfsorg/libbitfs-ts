# @bitfs/libbitfs

TypeScript client library for BitFS -- a peer-to-peer encrypted file system on blockchain.

Mirrors the functionality of [libbitfs-go](https://github.com/bitfsorg/libbitfs-go) with full wire-format compatibility. Cross-language test vectors verify interoperability between the Go and TypeScript implementations.

## Features

- **Method 42 encryption** -- ECDH key agreement + AES-256-GCM with three access modes (Private, Free, Paid)
- **HD wallet** -- BIP39 mnemonic, BIP44 key derivation (m/44'/236'), Argon2id seed encryption
- **Metanet DAG** -- TLV serialization (49 tag types), directory operations, Merkle tree, path/link resolution
- **SPV verification** -- block header chain validation, Proof-of-Work checks, Merkle proof verification
- **Atomic transactions** -- MutationBatch builder for multi-operation transaction construction
- **x402 payments** -- HTTP 402 protocol, HTLC script construction, invoice management
- **Content storage** -- content-addressed store, LZW/GZIP compression, chunking with recombination hashes
- **Revenue sharing** -- distribution algorithm, registry/share/ISO pool serialization
- **Paymail** -- BRFC capability discovery, PKI resolution, `bitfs://` URI parsing
- **Network** -- BlockchainService interface, RPC client, SPV client, network presets

ESM-first. Works in Node.js 18+ and modern browsers. Strict TypeScript throughout (`strict: true`, zero `any` types).

## Install

```bash
npm install @bitfs/libbitfs @bsv/sdk
```

`@bsv/sdk` is a required peer dependency.

## Modules

| Module | Description |
|--------|-------------|
| `method42` | ECDH encryption engine (AES-256-GCM, three access modes: Private/Free/Paid) |
| `wallet` | HD wallet (BIP39/BIP44 m/44'/236', Argon2id seed encryption, vault management) |
| `metanet` | Metanet DAG types, TLV serialization, directory ops, Merkle tree, CLTV access |
| `tx` | OP_RETURN builder/parser, fee estimation, MutationBatch atomic transaction builder |
| `spv` | Block headers, Merkle proofs, PoW validation, SPV transaction verification |
| `storage` | Content-addressed file store, compression (LZW/GZIP), chunking, ContentResolver |
| `network` | BlockchainService interface, RPCClient, SPVClient, network presets |
| `x402` | HTTP 402 payment protocol, HTLC scripts, invoice creation, payment verification |
| `paymail` | Paymail discovery, PKI resolution, BRFC IDs, `bitfs://` URI parsing |
| `config` | Configuration file parsing (key=value format), validation |
| `revshare` | Revenue share entries, distribution algorithm, binary serialization |

## Quick Start

### Encrypt and decrypt a file (Method 42)

```typescript
import { PrivateKey } from '@bsv/sdk'
import { method42 } from '@bitfs/libbitfs'

const owner = PrivateKey.fromRandom()
const pubKey = owner.toPublicKey()
const plaintext = new TextEncoder().encode('hello world')

// Encrypt with Private access (only the owner can decrypt)
const { ciphertext, keyHash } = await method42.encrypt(
  plaintext, owner, pubKey, method42.Access.Private
)

// Decrypt
const { plaintext: decrypted } = await method42.decrypt(
  ciphertext, owner, pubKey, keyHash, method42.Access.Private
)
```

### Create an HD wallet

```typescript
import { wallet } from '@bitfs/libbitfs'

const mnemonic = wallet.generateMnemonic(wallet.MNEMONIC_12_WORDS)
const seed = wallet.seedFromMnemonic(mnemonic, '')
const w = new wallet.Wallet(seed, wallet.MainNet)

// Derive a file key for vault 0, file index 5
const { privateKey, publicKey } = w.deriveFileKey(0, 5)
```

### Build a Metanet transaction

```typescript
import { tx, metanet } from '@bitfs/libbitfs'

const batch = new tx.MutationBatch()
batch.createRoot(parentTxId, parentVout, rootPubKey, payload)
batch.createChild(parentTxId, parentVout, childPubKey, payload)
const result = batch.build(utxos, feeKey)
```

## Sub-path Imports

Each module is available as a direct sub-path import:

```typescript
import { encrypt, decrypt, Access } from '@bitfs/libbitfs/method42'
import { Wallet, generateMnemonic } from '@bitfs/libbitfs/wallet'
import { MutationBatch } from '@bitfs/libbitfs/tx'
import { verifyMerkleProof } from '@bitfs/libbitfs/spv'
```

This enables tree-shaking -- bundlers will only include the modules you actually use.

## Browser Support

9 of 11 modules work in browsers without modification:

| Module | Browser | Node.js | Notes |
|--------|---------|---------|-------|
| method42 | Yes | Yes | |
| wallet | Yes | Yes | |
| metanet | Yes | Yes | |
| tx | Yes | Yes | |
| spv | Yes | Yes | |
| x402 | Yes | Yes | |
| paymail | Yes | Yes | |
| network | Yes | Yes | |
| revshare | Yes | Yes | |
| config | Partial | Yes | `loadConfig`/`saveConfig` require Node.js `fs`; parsing functions work everywhere |
| storage | Partial | Yes | `FileStore` requires Node.js `fs`; `MemoryStore`, compression, and chunking work everywhere |

## Dependencies

- **`@bsv/sdk`** (peer) -- BSV transaction primitives and elliptic curve operations
- **`@noble/hashes`** -- SHA-256, HMAC, HKDF (audited, zero-dependency)

No other runtime dependencies.

## Testing

```bash
npm test          # run all tests (vitest)
npm run typecheck # type-check without emitting
```

875+ tests across 31 test files. Tests use `vitest` and run in Node.js.

## API Reference

All public APIs are fully typed. See the generated `.d.ts` declaration files in `dist/` after building, or browse the source in `src/*/index.ts` for each module's complete export surface.

```bash
npm run build  # generates dist/ with declarations
```

## License

[Open BSV License](LICENSE)
