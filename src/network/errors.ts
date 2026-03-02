// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import { BitfsError } from '../errors.js'

/** The client could not connect to the node. */
export class ConnectionFailedError extends BitfsError {
  constructor(message: string) {
    super(`network: connection failed: ${message}`, 'ERR_CONNECTION_FAILED')
    this.name = 'ConnectionFailedError'
  }
}

/** Authentication (e.g., RPC credentials) was rejected. */
export class AuthFailedError extends BitfsError {
  constructor(message: string) {
    super(`network: authentication failed: ${message}`, 'ERR_AUTH_FAILED')
    this.name = 'AuthFailedError'
  }
}

/** The requested transaction does not exist. */
export class TxNotFoundError extends BitfsError {
  constructor(message: string) {
    super(`network: transaction not found: ${message}`, 'ERR_TX_NOT_FOUND')
    this.name = 'TxNotFoundError'
  }
}

/** The node rejected the broadcast transaction. */
export class BroadcastRejectedError extends BitfsError {
  constructor(message: string) {
    super(`network: broadcast rejected: ${message}`, 'ERR_BROADCAST_REJECTED')
    this.name = 'BroadcastRejectedError'
  }
}

/** The node returned a malformed or unexpected response. */
export class InvalidResponseError extends BitfsError {
  constructor(message: string) {
    super(`network: invalid response: ${message}`, 'ERR_INVALID_RESPONSE')
    this.name = 'InvalidResponseError'
  }
}

/** An RPC-level error from the node. */
export class RPCError extends BitfsError {
  constructor(
    public readonly rpcCode: number,
    message: string,
  ) {
    super(`network: rpc error ${rpcCode}: ${message}`, 'ERR_RPC')
    this.name = 'RPCError'
  }
}
