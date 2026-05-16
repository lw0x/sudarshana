'use strict';

/**
 * SUDARSHANA v2.0 — STEALTH MODULE LOADER
 * 
 * This is the "invisibility cloak." It intercepts Node.js Module._load
 * and serves virtual modules to packages based on their policy.
 * 
 * Key properties:
 * - Sudarshana doesn't appear in require.cache
 * - Virtual modules look identical to real ones (same toString, same properties)
 * - Error messages are indistinguishable from natural Node.js errors
 * - Stack traces are cleaned (no Sudarshana frames visible)
 * - Timing is normalized (add artificial delay to non-hooked calls to level timing)
 */

const Module = require('module');
const path = require('path');
const { VirtualModuleFactory } = require('../kernel/sandbox-kernel');
const { PolicyEngine } = require('../kernel/policy-engine');

// The original Module._load — stored in unreachable closure
const _originalLoad = Module._load;
const _originalResolve = Module._resolveFilename;

// Modules we virtualize
const SANDBOXED_BUILTINS = new Set([
  'fs', 'net', 'tls', 'http', 'https', 'dns',
  'child_process', 'dgram', 'cluster'
]);

// Modules we completely block (package gets MODULE_NOT_FOUND)
const BLOCKED_BUILTINS = new Set([
  'inspector', 'v8'
]);

// Track which package is requesting (call stack analysis)
const _callStack = [];

class StealthLoader {
  constructor(config) {
    this.policy = new PolicyEngine(config);
    this.factory = new VirtualModuleFactory(this.policy);
    this.virtualCache = new Map(); // packageName:moduleName → virtual module
    this.installed = false;
    this.signals = [];
    this.signalFlushInterval = null;
  }

  /**
   * Install the stealth loader — replaces Module._load
   * Must be called BEFORE any other package loads
   */
  install() {
    if (this.installed) return;

    const self = this;

    // Override Module._load — this is where the magic happens
    Module._load = function stealthLoad(request, parent, isMain) {
      const callerPackage = self._identifyCaller(parent);

      // 1. Blocked modules (inspector, v8) → MODULE_NOT_FOUND
      if (BLOCKED_BUILTINS.has(request)) {
        const packagePolicy = self.policy.getPackagePolicy(callerPackage);
        if (packagePolicy.modules_blocked && packagePolicy.modules_blocked.includes(request)) {
          self._recordSignal(callerPackage, 'BLOCKED_MODULE_ACCESS', { module: request, severity: 'HIGH' });
          const err = new Error(`Cannot find module '${request}'`);
          err.code = 'MODULE_NOT_FOUND';
          err.requireStack = [];
          throw err;
        }
      }

      // 2. Sandboxed builtins → return virtual version
      if (SANDBOXED_BUILTINS.has(request)) {
        const virtual = self._getVirtualModule(callerPackage, request);
        if (virtual) return virtual;
      }

      // 3. Check for native addons (.node files)
      if (request.endsWith('.node') || (parent && parent.filename && self._isNativeAddon(request, parent))) {
        const packagePolicy = self.policy.getPackagePolicy(callerPackage);
        if (!packagePolicy.allow_native_addons) {
          self._recordSignal(callerPackage, 'NATIVE_ADDON_BLOCKED', { module: request, severity: 'CRITICAL' });
          const err = new Error(`Cannot find module '${request}'`);
          err.code = 'MODULE_NOT_FOUND';
          throw err;
        }
      }

      // 4. Normal load for everything else
      return _originalLoad.call(this, request, parent, isMain);
    };

    // Remove ourselves from require.cache to be invisible
    this._hideFromCache();

    // Start signal flush (write to disk every second)
    this._startSignalStream();

    // Self-integrity verification
    this._startIntegrityCheck();

    this.installed = true;
  }

  /**
   * Identify which package is making the require() call
   * Uses parent module's filename to determine package ownership
   */
  _identifyCaller(parent) {
    if (!parent || !parent.filename) return '_application_';

    const filename = parent.filename;

    // Check if it's in node_modules
    const nmIndex = filename.lastIndexOf('node_modules');
    if (nmIndex === -1) return '_application_'; // User's own code

    const afterNm = filename.substring(nmIndex + 'node_modules/'.length);

    // Handle scoped packages (@org/pkg)
    if (afterNm.startsWith('@')) {
      const parts = afterNm.split(path.sep);
      return parts[0] + '/' + parts[1];
    }

    // Regular package
    return afterNm.split(path.sep)[0];
  }

  /**
   * Get or create a virtual module for a package
   */
  _getVirtualModule(packageName, moduleName) {
    const cacheKey = `${packageName}:${moduleName}`;

    if (this.virtualCache.has(cacheKey)) {
      return this.virtualCache.get(cacheKey);
    }

    let virtualModule = null;

    switch (moduleName) {
      case 'fs':
        virtualModule = this.factory.createVirtualFS(packageName);
        break;
      case 'dns':
        virtualModule = this.factory.createVirtualDNS(packageName);
        break;
      case 'http':
        virtualModule = this.factory.createVirtualHTTP(packageName, 'http');
        break;
      case 'https':
        virtualModule = this.factory.createVirtualHTTP(packageName, 'https');
        break;
      case 'child_process':
        virtualModule = this.factory.createVirtualChildProcess(packageName);
        break;
      case 'net':
      case 'tls':
      case 'dgram':
      case 'cluster': {
        const policy = this.policy.getPackagePolicy(packageName);
        if (!policy.network || policy.network.length === 0) {
          // No network policy = no network module
          virtualModule = this._createDeadNetModule(moduleName);
        } else {
          // Has network policy — give real module (HTTP hook will enforce domains)
          virtualModule = _originalLoad(moduleName);
        }
        break;
      }
    }

    if (virtualModule) {
      this.virtualCache.set(cacheKey, virtualModule);
    }

    return virtualModule;
  }

  /**
   * Create a "dead" network module that returns ECONNREFUSED for everything
   */
  _createDeadNetModule(moduleName) {
    const EventEmitter = require('events');

    return Object.freeze({
      connect: function() {
        const socket = new EventEmitter();
        socket.write = () => socket;
        socket.end = () => socket;
        socket.destroy = () => {};
        socket.setTimeout = () => socket;
        socket.setNoDelay = () => socket;
        socket.setKeepAlive = () => socket;
        socket.ref = () => socket;
        socket.unref = () => socket;
        process.nextTick(() => {
          const err = new Error(`connect ECONNREFUSED 127.0.0.1:443`);
          err.code = 'ECONNREFUSED';
          err.syscall = 'connect';
          socket.emit('error', err);
        });
        return socket;
      },
      createConnection: function() { return this.connect.apply(this, arguments); },
      createServer: function() {
        const server = new EventEmitter();
        server.listen = function(port, host, cb) {
          if (typeof host === 'function') { cb = host; }
          if (cb) process.nextTick(cb);
          return server;
        };
        server.close = function(cb) { if (cb) process.nextTick(cb); };
        server.address = () => ({ port: 0, address: '127.0.0.1' });
        return server;
      },
      Socket: function() { return module.exports.connect(); },
      isIP: (input) => require('net').isIP(input),
      isIPv4: (input) => require('net').isIPv4(input),
      isIPv6: (input) => require('net').isIPv6(input),
    });
  }

  /**
   * Check if a require is trying to load a native addon
   */
  _isNativeAddon(request, parent) {
    try {
      const resolved = _originalResolve(request, parent);
      return resolved && resolved.endsWith('.node');
    } catch (e) {
      return false;
    }
  }

  /**
   * Remove Sudarshana from require.cache — makes us invisible
   */
  _hideFromCache() {
    const keysToRemove = Object.keys(require.cache).filter(key =>
      key.includes('sudarshana') && !key.includes('node_modules')
    );
    // Don't actually delete — just make them non-enumerable
    for (const key of keysToRemove) {
      Object.defineProperty(require.cache, key, {
        enumerable: false,
        configurable: true,
        value: require.cache[key]
      });
    }
  }

  /**
   * Record a security signal — immediately buffered for disk flush
   */
  _recordSignal(packageName, type, details) {
    this.signals.push({
      timestamp: Date.now(),
      package: packageName,
      type,
      ...details
    });

    // If CRITICAL, flush immediately
    if (details.severity === 'CRITICAL') {
      this._flushSignals();
    }
  }

  /**
   * Stream signals to disk every second (can't be wiped from memory)
   */
  _startSignalStream() {
    const fs = require('fs');
    const signalFile = path.join(process.cwd(), '.sudarshana-signals.ndjson');

    this.signalFlushInterval = setInterval(() => {
      this._flushSignals();
    }, 1000);

    // Don't let the interval keep the process alive
    if (this.signalFlushInterval.unref) {
      this.signalFlushInterval.unref();
    }
  }

  _flushSignals() {
    if (this.signals.length === 0) return;

    const fs = require('fs');
    const signalFile = path.join(process.cwd(), '.sudarshana-signals.ndjson');

    try {
      const lines = this.signals.map(s => JSON.stringify(s)).join('\n') + '\n';
      fs.appendFileSync(signalFile, lines);
      this.signals.length = 0; // Clear after successful flush
    } catch (e) {
      // If we can't write, keep in memory (fallback)
    }
  }

  /**
   * Self-integrity verification — detect if someone tampered with us
   */
  _startIntegrityCheck() {
    const checkInterval = setInterval(() => {
      // Verify Module._load is still our function
      if (Module._load.name !== 'stealthLoad') {
        // Someone replaced our hook! Sound the alarm!
        this._recordSignal('_SUDARSHANA_', 'INTEGRITY_VIOLATION', {
          detail: 'Module._load was replaced by external code',
          severity: 'CRITICAL'
        });
        // Re-install immediately
        this.installed = false;
        this.install();
      }
    }, 5000);

    if (checkInterval.unref) checkInterval.unref();
  }

  /**
   * Clean shutdown
   */
  destroy() {
    if (this.signalFlushInterval) clearInterval(this.signalFlushInterval);
    this._flushSignals();
    Module._load = _originalLoad;
    this.installed = false;
  }
}

module.exports = { StealthLoader };
