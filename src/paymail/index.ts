// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

export {
  AddressType,
  addressTypeString,
  type ParsedURI,
  type PaymailCapabilities,
  type PKIResponse,
  type PaymentOutput,
  type HTTPClient,
  type PostClient,
} from './types.js'

export {
  parseURI,
  isPubKeyHex,
  validateCompressedPubKey,
  bytesToHex,
} from './uri.js'

export {
  discoverCapabilities,
  resolvePKI,
  resolvePaymentDestination,
  defaultHTTPClient,
  defaultPostClient,
  MAX_PAYMAIL_RESPONSE_SIZE,
} from './discover.js'

export {
  computeBRFCID,
  BRFC_BITFS_BROWSE,
  BRFC_BITFS_BUY,
  BRFC_BITFS_SELL,
} from './brfc.js'

export {
  PaymailError,
  InvalidURIError,
  PaymailDiscoveryError,
  PKIResolutionError,
  InvalidPubKeyError,
  AddressResolutionError,
} from './errors.js'
