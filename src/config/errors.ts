// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import { BitfsError } from '../errors.js'

/** The network name is not recognized (must be "mainnet", "testnet", or "regtest"). */
export class InvalidNetworkError extends BitfsError {
  constructor() {
    super(
      'config: invalid network (must be "mainnet", "testnet", or "regtest")',
      'ERR_INVALID_NETWORK',
    )
    this.name = 'InvalidNetworkError'
  }
}

/** The listen address is malformed (must be host:port). */
export class InvalidListenAddrError extends BitfsError {
  constructor(detail?: string) {
    const msg = detail
      ? `config: invalid listen address: ${detail}`
      : 'config: invalid listen address'
    super(msg, 'ERR_INVALID_LISTEN_ADDR')
    this.name = 'InvalidListenAddrError'
  }
}

/** The log level is not recognized (must be "debug", "info", "warn", or "error"). */
export class InvalidLogLevelError extends BitfsError {
  constructor() {
    super(
      'config: invalid log level (must be "debug", "info", "warn", or "error")',
      'ERR_INVALID_LOG_LEVEL',
    )
    this.name = 'InvalidLogLevelError'
  }
}

/** The data directory path is empty. */
export class EmptyDataDirError extends BitfsError {
  constructor() {
    super('config: data directory must not be empty', 'ERR_EMPTY_DATA_DIR')
    this.name = 'EmptyDataDirError'
  }
}

/** The configuration file does not exist. */
export class ConfigNotFoundError extends BitfsError {
  constructor() {
    super('config: configuration file not found', 'ERR_CONFIG_NOT_FOUND')
    this.name = 'ConfigNotFoundError'
  }
}

/** A line in the config file is malformed. */
export class InvalidConfigLineError extends BitfsError {
  constructor(line: number, content: string) {
    super(
      `config: invalid configuration line: line ${line}: ${JSON.stringify(content)}`,
      'ERR_INVALID_CONFIG_LINE',
    )
    this.name = 'InvalidConfigLineError'
  }
}
