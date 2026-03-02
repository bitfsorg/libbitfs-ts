// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import { BitfsError } from '../errors.js'

/** Base class for all paymail errors. */
export class PaymailError extends BitfsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'PaymailError'
  }
}

/** The URI does not match bitfs:// scheme or is malformed. */
export class InvalidURIError extends PaymailError {
  constructor(detail: string) {
    super(`paymail: invalid bitfs:// URI: ${detail}`, 'ERR_INVALID_URI')
    this.name = 'InvalidURIError'
  }
}

/** The .well-known/bsvalias fetch failed. */
export class PaymailDiscoveryError extends PaymailError {
  constructor(detail: string) {
    super(`paymail: capability discovery failed: ${detail}`, 'ERR_PAYMAIL_DISCOVERY')
    this.name = 'PaymailDiscoveryError'
  }
}

/** The Paymail PKI endpoint returned an error. */
export class PKIResolutionError extends PaymailError {
  constructor(detail: string) {
    super(`paymail: PKI resolution failed: ${detail}`, 'ERR_PKI_RESOLUTION')
    this.name = 'PKIResolutionError'
  }
}

/** A public key is not a valid compressed secp256k1 key. */
export class InvalidPubKeyError extends PaymailError {
  constructor(detail: string) {
    super(`paymail: invalid compressed public key: ${detail}`, 'ERR_INVALID_PUB_KEY')
    this.name = 'InvalidPubKeyError'
  }
}

/** The P2P payment destination resolution failed. */
export class AddressResolutionError extends PaymailError {
  constructor(detail: string) {
    super(`paymail: address resolution failed: ${detail}`, 'ERR_ADDRESS_RESOLUTION')
    this.name = 'AddressResolutionError'
  }
}
