// @bitfs/libbitfs — browser entry.
//
// Mirrors ./index.ts but wires the storage namespace to the browser-safe
// storage barrel (no FileStore, no node:fs/node:path imports), so bundlers
// resolving the "browser" exports condition never see Node built-ins.
// Keep in sync with ./index.ts when adding top-level exports.

export { BitfsError } from './errors.js'
export { hexToBytes } from './util.js'

export * as method42 from './method42/index.js'
export * as wallet from './wallet/index.js'
export * as config from './config/index.js'
export * as metanet from './metanet/index.js'
export * as storage from './storage/index.browser.js'
export * as tx from './tx/index.js'
export * as spv from './spv/index.js'
export * as network from './network/index.js'
export * as payment from './payment/index.js'
export * as paymail from './paymail/index.js'
export * as revshare from './revshare/index.js'
