// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { join } from 'path'
import { mkdtemp, rm, readFile, writeFile, stat, chmod } from 'fs/promises'
import { tmpdir } from 'os'

import {
  defaultDataDir,
  defaultConfig,
  parseConfigString,
  serializeConfig,
  loadConfig,
  saveConfig,
  validateConfig,
  configPath,
} from '../config.js'

import {
  InvalidNetworkError,
  InvalidListenAddrError,
  InvalidLogLevelError,
  EmptyDataDirError,
  ConfigNotFoundError,
  InvalidConfigLineError,
} from '../errors.js'

// ---------------------------------------------------------------------------
// defaultConfig tests
// ---------------------------------------------------------------------------

describe('defaultConfig', () => {
  it('returns sensible defaults', () => {
    const cfg = defaultConfig()
    expect(cfg.listenAddr).toBe(':8080')
    expect(cfg.network).toBe('mainnet')
    expect(cfg.logLevel).toBe('info')
    expect(cfg.logFile).toBe('')
  })

  it('has a non-empty dataDir', () => {
    const cfg = defaultConfig()
    expect(cfg.dataDir).not.toBe('')
  })
})

// ---------------------------------------------------------------------------
// defaultDataDir tests
// ---------------------------------------------------------------------------

describe('defaultDataDir', () => {
  it('ends with .bitfs', () => {
    const dir = defaultDataDir()
    expect(dir.endsWith('.bitfs')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// parseConfigString tests
// ---------------------------------------------------------------------------

describe('parseConfigString', () => {
  it('parses valid key=value string', () => {
    const content = 'network=testnet\nloglevel=debug\n'
    const cfg = parseConfigString(content)
    expect(cfg.network).toBe('testnet')
    expect(cfg.logLevel).toBe('debug')
  })

  it('ignores comments and blank lines', () => {
    const content = [
      '# This is a comment',
      'network = testnet',
      '',
      '# Another comment',
      'loglevel = debug',
    ].join('\n')

    const cfg = parseConfigString(content)
    expect(cfg.network).toBe('testnet')
    expect(cfg.logLevel).toBe('debug')
    // Unset fields retain defaults.
    expect(cfg.listenAddr).toBe(':8080')
  })

  it('silently ignores unknown keys', () => {
    const content = 'futurekey = futurevalue\nnetwork = testnet\n'
    const cfg = parseConfigString(content)
    expect(cfg.network).toBe('testnet')
  })

  it('throws on lines without =', () => {
    const content = 'this-is-not-key-value\n'
    expect(() => parseConfigString(content)).toThrow(InvalidConfigLineError)
  })

  it('handles empty value', () => {
    const content = 'network=\n'
    const cfg = parseConfigString(content)
    expect(cfg.network).toBe('')
  })

  it('handles multiple = signs (splits on first only)', () => {
    const content = 'logfile=/tmp/a=b.log\n'
    const cfg = parseConfigString(content)
    expect(cfg.logFile).toBe('/tmp/a=b.log')
  })

  it('trims whitespace around = and on the line', () => {
    const content = '  network = testnet  \n'
    const cfg = parseConfigString(content)
    expect(cfg.network).toBe('testnet')
  })

  it('parses all known keys', () => {
    const content = [
      'datadir = /tmp/test-bitfs',
      'listen = :9000',
      'network = testnet',
      'loglevel = debug',
      'logfile = /tmp/bitfs.log',
    ].join('\n')

    const cfg = parseConfigString(content)
    expect(cfg.dataDir).toBe('/tmp/test-bitfs')
    expect(cfg.listenAddr).toBe(':9000')
    expect(cfg.network).toBe('testnet')
    expect(cfg.logLevel).toBe('debug')
    expect(cfg.logFile).toBe('/tmp/bitfs.log')
  })
})

// ---------------------------------------------------------------------------
// serializeConfig tests
// ---------------------------------------------------------------------------

describe('serializeConfig', () => {
  it('output contains header', () => {
    const cfg = defaultConfig()
    const output = serializeConfig(cfg)
    expect(output).toContain('# BitFS Configuration')
  })

  it('output contains all keys in key = value format', () => {
    const cfg = {
      dataDir: '/data',
      listenAddr: ':9090',
      network: 'testnet',
      logLevel: 'warn',
      logFile: '/var/log/bitfs.log',
    }
    const output = serializeConfig(cfg)

    for (const key of ['datadir', 'listen', 'network', 'loglevel', 'logfile']) {
      expect(output).toContain(`${key} = `)
    }
  })
})

// ---------------------------------------------------------------------------
// Round-trip: serialize then parse
// ---------------------------------------------------------------------------

describe('round-trip', () => {
  it('serialize then parse returns same config', () => {
    const original = {
      dataDir: '/tmp/test-bitfs',
      listenAddr: ':9000',
      network: 'testnet',
      logLevel: 'debug',
      logFile: '/tmp/bitfs.log',
    }

    const serialized = serializeConfig(original)
    const loaded = parseConfigString(serialized)

    expect(loaded.dataDir).toBe(original.dataDir)
    expect(loaded.listenAddr).toBe(original.listenAddr)
    expect(loaded.network).toBe(original.network)
    expect(loaded.logLevel).toBe(original.logLevel)
    expect(loaded.logFile).toBe(original.logFile)
  })
})

// ---------------------------------------------------------------------------
// validateConfig tests
// ---------------------------------------------------------------------------

describe('validateConfig', () => {
  it('accepts default config', () => {
    const cfg = defaultConfig()
    expect(() => validateConfig(cfg)).not.toThrow()
  })

  it('throws on empty dataDir', () => {
    const cfg = defaultConfig()
    cfg.dataDir = ''
    expect(() => validateConfig(cfg)).toThrow(EmptyDataDirError)
  })

  it('throws on invalid network', () => {
    const cfg = defaultConfig()
    cfg.network = 'devnet'
    expect(() => validateConfig(cfg)).toThrow(InvalidNetworkError)
  })

  it('throws on empty network', () => {
    const cfg = defaultConfig()
    cfg.network = ''
    expect(() => validateConfig(cfg)).toThrow(InvalidNetworkError)
  })

  it('throws on invalid listen address (no colon)', () => {
    const cfg = defaultConfig()
    cfg.listenAddr = 'not-a-valid-addr'
    expect(() => validateConfig(cfg)).toThrow(InvalidListenAddrError)
  })

  it('throws on empty listen address', () => {
    const cfg = defaultConfig()
    cfg.listenAddr = ''
    expect(() => validateConfig(cfg)).toThrow(InvalidListenAddrError)
  })

  it('throws on invalid log level', () => {
    const cfg = defaultConfig()
    cfg.logLevel = 'verbose'
    expect(() => validateConfig(cfg)).toThrow(InvalidLogLevelError)
  })

  it('accepts all valid networks', () => {
    for (const network of ['mainnet', 'testnet', 'regtest']) {
      const cfg = defaultConfig()
      cfg.network = network
      expect(() => validateConfig(cfg)).not.toThrow()
    }
  })

  it('accepts all valid log levels', () => {
    for (const level of ['debug', 'info', 'warn', 'error']) {
      const cfg = defaultConfig()
      cfg.logLevel = level
      expect(() => validateConfig(cfg)).not.toThrow()
    }
  })

  it('log level validation is case-insensitive', () => {
    const levels = ['INFO', 'Debug', 'WARN', 'Error', 'dEbUg']
    for (const level of levels) {
      const cfg = defaultConfig()
      cfg.logLevel = level
      expect(() => validateConfig(cfg)).not.toThrow()
    }
  })

  it('accepts valid listen address variants', () => {
    const addrs = [
      '127.0.0.1:80',
      '0.0.0.0:443',
      ':8080',
      'localhost:3000',
      '[::1]:8080',
    ]
    for (const addr of addrs) {
      const cfg = defaultConfig()
      cfg.listenAddr = addr
      expect(() => validateConfig(cfg)).not.toThrow()
    }
  })
})

// ---------------------------------------------------------------------------
// configPath tests
// ---------------------------------------------------------------------------

describe('configPath', () => {
  it('returns correct path', () => {
    const got = configPath('/home/user/.bitfs')
    expect(got).toBe(join('/home/user/.bitfs', 'config'))
  })

  it('handles trailing slash', () => {
    const got = configPath('/foo/')
    expect(got).toBe(join('/foo', 'config'))
  })
})

// ---------------------------------------------------------------------------
// loadConfig / saveConfig (file I/O tests)
// ---------------------------------------------------------------------------

describe('loadConfig / saveConfig', () => {
  let tmpDir: string

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'bitfs-config-test-'))
  })

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true })
  })

  it('round-trip: save then load returns same config', async () => {
    const path = join(tmpDir, 'config')
    const original = {
      dataDir: '/tmp/test-bitfs',
      listenAddr: ':9000',
      network: 'testnet',
      logLevel: 'debug',
      logFile: '/tmp/bitfs.log',
    }

    await saveConfig(path, original)
    const loaded = await loadConfig(path)

    expect(loaded.dataDir).toBe(original.dataDir)
    expect(loaded.listenAddr).toBe(original.listenAddr)
    expect(loaded.network).toBe(original.network)
    expect(loaded.logLevel).toBe(original.logLevel)
    expect(loaded.logFile).toBe(original.logFile)
  })

  it('saveConfig creates parent directories', async () => {
    const path = join(tmpDir, 'subdir', 'config')
    const cfg = defaultConfig()

    await saveConfig(path, cfg)

    const info = await stat(path)
    expect(info.isFile()).toBe(true)
  })

  it('saveConfig creates file with 0o600 permissions', async () => {
    const path = join(tmpDir, 'test.conf')
    await saveConfig(path, { ...defaultConfig(), network: 'mainnet' })

    const info = await stat(path)
    // Check permissions (mask off file type bits).
    const perm = info.mode & 0o777
    expect(perm).toBe(0o600)
  })

  it('loadConfig throws ConfigNotFoundError for missing file', async () => {
    await expect(loadConfig('/nonexistent/path/config')).rejects.toThrow(
      ConfigNotFoundError,
    )
  })

  it('loadConfig throws InvalidConfigLineError for malformed lines', async () => {
    const path = join(tmpDir, 'config')
    await writeFile(path, 'this-is-not-key-value\n', { mode: 0o600 })

    await expect(loadConfig(path)).rejects.toThrow(InvalidConfigLineError)
  })

  it('loadConfig handles comments and blank lines', async () => {
    const path = join(tmpDir, 'config')
    const content = [
      '# This is a comment',
      'network = testnet',
      '',
      '# Another comment',
      'loglevel = debug',
    ].join('\n')
    await writeFile(path, content, { mode: 0o600 })

    const cfg = await loadConfig(path)
    expect(cfg.network).toBe('testnet')
    expect(cfg.logLevel).toBe('debug')
    expect(cfg.listenAddr).toBe(':8080') // default
  })

  it('loadConfig ignores unknown keys', async () => {
    const path = join(tmpDir, 'config')
    await writeFile(path, 'futurekey = futurevalue\nnetwork = testnet\n', {
      mode: 0o600,
    })

    const cfg = await loadConfig(path)
    expect(cfg.network).toBe('testnet')
  })

  it('saved config contains header comment', async () => {
    const path = join(tmpDir, 'config')
    await saveConfig(path, defaultConfig())

    const data = await readFile(path, 'utf-8')
    expect(data).toContain('# BitFS Configuration')
  })

  it('saved config contains all keys', async () => {
    const path = join(tmpDir, 'config')
    const cfg = {
      dataDir: '/data',
      listenAddr: ':9090',
      network: 'testnet',
      logLevel: 'warn',
      logFile: '/var/log/bitfs.log',
    }
    await saveConfig(path, cfg)

    const data = await readFile(path, 'utf-8')
    for (const key of ['datadir', 'listen', 'network', 'loglevel', 'logfile']) {
      expect(data).toContain(`${key} = `)
    }
  })

  it('loadConfig with permission denied does not throw ConfigNotFoundError', async () => {
    if (process.getuid?.() === 0) return // skip as root

    const path = join(tmpDir, 'config')
    await writeFile(path, 'network=testnet\n', { mode: 0o600 })
    await chmod(path, 0o000)

    try {
      await expect(loadConfig(path)).rejects.toThrow()
      // The error should NOT be ConfigNotFoundError.
      try {
        await loadConfig(path)
      } catch (err) {
        expect(err).not.toBeInstanceOf(ConfigNotFoundError)
      }
    } finally {
      // Restore permissions for cleanup.
      await chmod(path, 0o600)
    }
  })
})
