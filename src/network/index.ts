// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

// Types and interfaces
export type {
  BlockchainService,
  UTXO,
  TxStatus,
  MerkleProofData,
  RPCConfig,
} from './types.js'
export { NetworkPresets, resolveConfig } from './types.js'

// Errors
export {
  ConnectionFailedError,
  AuthFailedError,
  TxNotFoundError,
  BroadcastRejectedError,
  InvalidResponseError,
  RPCError,
} from './errors.js'

// RPCClient
export { RPCClient, hexToBytes, bytesToHex, reverseBytes, btcToSat } from './rpc.js'

// SPVClient
export {
  SPVClient,
  deserializeHeader,
  serializeHeader,
  computeHeaderHash,
  computeMerkleRoot,
} from './spvclient.js'
export type {
  BlockHeader,
  HeaderStore,
  SPVMerkleProof,
  VerifyResult,
} from './spvclient.js'

// Mock (for testing)
export { MockBlockchainService, MemHeaderStore } from './mock.js'
