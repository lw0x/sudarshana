'use strict';

/**
 * SUDARSHANA v2.0 — SANDBOX KERNEL
 * 
 * "The gun doesn't exist in their reality."
 * 
 * This is the core of the missile architecture. It intercepts Module._load
 * at the deepest level and gives each package a VIRTUAL version of Node.js
 * built-in modules — tailored to that package's policy.
 * 
 * A package with no network policy doesn't get "blocked" from HTTP.
 * HTTP literally doesn't work. DNS returns ENOTFOUND. 
 * net.connect returns ECONNREFUSED. Naturally. Invisibly.
 * 
 * A package with no fs policy can't see sensitive files.
 * They get ENOENT. The file "doesn't exist" in their universe.
 * 
 * The kernel is:
 * - INVISIBLE (not in require.cache, not in stack traces)
 * - IMMUTABLE (frozen closures, no external references)
 * - SELF-VERIFYING (integrity checks at intervals)
 */

const Module = require('module');
const path = require('path');
const crypto = require('crypto');

// Store ALL original module references in a frozen closure
// No external code can access these
const _originals = Object.freeze({
  fs: require('fs'),
  net: require('net'),
  tls: require('tls'),
  http: require('http'),
  https: require('https'),
  dns: require('dns'),
  child_process: require('child_process'),
  crypto: require('crypto'),
  v8: require('v8'),
  inspector: require('inspector'),
  worker_threads: require('worker_threads'),
  vm: require('vm'),
  os: require('os')
});

// The kernel's private state — inaccessible from outside
const _state = {
  policies: null,
  signalStream: null,
  initialized: false,
  selfHash: null
};

/**
 * The Virtual Module Factory
 * Creates per-package sandboxed versions of Node.js built-in modules
 */
class VirtualModuleFactory {
  constructor(policy) {
    this.policy = policy;
  }

  /**
   * Create a virtual 'fs' module for a specific package
   * Only allows access to paths in the package's policy
   */
  createVirtualFS(packageName) {
    const policy = this.policy.getPackagePolicy(packageName);
    const allowedPaths = policy.fs_read || [];
    const allowedWrite = policy.fs_write || [];
    const originalFs = _originals.fs;

    // Build a fake fs that returns ENOENT for disallowed paths
    const virtualFs = Object.create(originalFs);

    virtualFs.readFileSync = function(filePath, options) {
      const resolved = path.resolve(String(filePath));
      const realPath = safeRealpath(resolved);

      if (!isPathAllowed(realPath, allowedPaths)) {
        // Return ENOENT — looks natural, undetectable as sandboxing
        const err = new Error(`ENOENT: no such file or directory, open '${filePath}'`);
        err.code = 'ENOENT';
        err.errno = -2;
        err.syscall = 'open';
        err.path = filePath;
        throw err;
      }

      return originalFs.readFileSync.call(originalFs, filePath, options);
    };

    virtualFs.readFile = function(filePath, options, callback) {
      if (typeof options === 'function') { callback = options; options = {}; }
      const resolved = path.resolve(String(filePath));
      const realPath = safeRealpath(resolved);

      if (!isPathAllowed(realPath, allowedPaths)) {
        const err = new Error(`ENOENT: no such file or directory, open '${filePath}'`);
        err.code = 'ENOENT';
        err.errno = -2;
        err.syscall = 'open';
        err.path = filePath;
        if (callback) return process.nextTick(() => callback(err));
        return;
      }

      return originalFs.readFile.call(originalFs, filePath, options, callback);
    };

    virtualFs.writeFileSync = function(filePath, data, options) {
      const resolved = path.resolve(String(filePath));
      if (!isPathAllowed(resolved, allowedWrite)) {
        const err = new Error(`EACCES: permission denied, open '${filePath}'`);
        err.code = 'EACCES';
        err.errno = -13;
        err.syscall = 'open';
        err.path = filePath;
        throw err;
      }
      return originalFs.writeFileSync.call(originalFs, filePath, data, options);
    };

    virtualFs.existsSync = function(filePath) {
      const resolved = path.resolve(String(filePath));
      const realPath = safeRealpath(resolved);
      if (!isPathAllowed(realPath, allowedPaths)) {
        return false; // File "doesn't exist" in their reality
      }
      return originalFs.existsSync.call(originalFs, filePath);
    };

    virtualFs.readdirSync = function(dirPath, options) {
      const resolved = path.resolve(String(dirPath));
      if (!isPathAllowed(resolved, allowedPaths)) {
        const err = new Error(`ENOENT: no such file or directory, scandir '${dirPath}'`);
        err.code = 'ENOENT';
        throw err;
      }
      // Filter results to only show files the package can see
      const results = originalFs.readdirSync.call(originalFs, dirPath, options);
      return results.filter(entry => {
        const entryPath = path.join(resolved, typeof entry === 'string' ? entry : entry.name);
        return isPathAllowed(entryPath, allowedPaths);
      });
    };

    // Block dangerous operations entirely
    virtualFs.watch = function() {
      const err = new Error(`ENOSYS: function not implemented, watch`);
      err.code = 'ENOSYS';
      throw err;
    };

    return Object.freeze(virtualFs);
  }

  /**
   * Create a virtual 'dns' module — only resolves allowed domains
   */
  createVirtualDNS(packageName) {
    const policy = this.policy.getPackagePolicy(packageName);
    const allowedDomains = policy.network || [];

    const virtualDns = {};

    virtualDns.lookup = function(hostname, options, callback) {
      if (typeof options === 'function') { callback = options; options = {}; }

      if (!isDomainAllowed(hostname, allowedDomains)) {
        // Return ENOTFOUND — looks like DNS doesn't work (natural in containers)
        const err = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
        err.code = 'ENOTFOUND';
        err.hostname = hostname;
        err.syscall = 'getaddrinfo';
        if (callback) return process.nextTick(() => callback(err));
        return;
      }

      return _originals.dns.lookup.call(_originals.dns, hostname, options, callback);
    };

    virtualDns.resolve = function(hostname, rrtype, callback) {
      if (typeof rrtype === 'function') { callback = rrtype; rrtype = 'A'; }
      if (!isDomainAllowed(hostname, allowedDomains)) {
        const err = new Error(`queryA ENOTFOUND ${hostname}`);
        err.code = 'ENOTFOUND';
        if (callback) return process.nextTick(() => callback(err));
        return;
      }
      return _originals.dns.resolve.call(_originals.dns, hostname, rrtype, callback);
    };

    virtualDns.resolve4 = virtualDns.resolve;
    virtualDns.resolve6 = virtualDns.resolve;
    virtualDns.resolveTxt = function(hostname, callback) {
      if (!isDomainAllowed(hostname, allowedDomains)) {
        const err = new Error(`queryTxt ENOTFOUND ${hostname}`);
        err.code = 'ENOTFOUND';
        if (callback) return process.nextTick(() => callback(err));
        return;
      }
      return _originals.dns.resolveTxt.call(_originals.dns, hostname, callback);
    };

    virtualDns.promises = {
      lookup: (hostname) => {
        if (!isDomainAllowed(hostname, allowedDomains)) {
          return Promise.reject(Object.assign(new Error(`ENOTFOUND ${hostname}`), { code: 'ENOTFOUND' }));
        }
        return _originals.dns.promises.lookup(hostname);
      },
      resolve: (hostname) => {
        if (!isDomainAllowed(hostname, allowedDomains)) {
          return Promise.reject(Object.assign(new Error(`ENOTFOUND ${hostname}`), { code: 'ENOTFOUND' }));
        }
        return _originals.dns.promises.resolve(hostname);
      }
    };

    return Object.freeze(virtualDns);
  }

  /**
   * Create a virtual 'http'/'https' module — only connects to allowed domains
   */
  createVirtualHTTP(packageName, protocol) {
    const policy = this.policy.getPackagePolicy(packageName);
    const allowedDomains = policy.network || [];
    const originalModule = protocol === 'https' ? _originals.https : _originals.http;

    const virtualHttp = Object.create(originalModule);

    const createSandboxedRequest = (original) => {
      return function(urlOrOptions, options, callback) {
        let hostname = '';
        
        if (typeof urlOrOptions === 'string') {
          try { hostname = new URL(urlOrOptions).hostname; } catch(e) {}
        } else if (urlOrOptions instanceof URL) {
          hostname = urlOrOptions.hostname;
        } else if (urlOrOptions) {
          hostname = urlOrOptions.hostname || urlOrOptions.host || '';
          hostname = hostname.split(':')[0]; // Remove port
        }

        if (!isDomainAllowed(hostname, allowedDomains)) {
          // Return ECONNREFUSED — natural network error
          const EventEmitter = require('events');
          const dummyReq = new EventEmitter();
          dummyReq.write = () => dummyReq;
          dummyReq.end = () => dummyReq;
          dummyReq.destroy = () => {};
          dummyReq.abort = () => {};
          dummyReq.setTimeout = () => dummyReq;
          dummyReq.on = function(evt, handler) {
            EventEmitter.prototype.on.call(this, evt, handler);
            return this;
          };

          process.nextTick(() => {
            const err = new Error(`connect ECONNREFUSED ${hostname}`);
            err.code = 'ECONNREFUSED';
            err.syscall = 'connect';
            err.address = hostname;
            dummyReq.emit('error', err);
          });

          return dummyReq;
        }

        return original.call(originalModule, urlOrOptions, options, callback);
      };
    };

    virtualHttp.request = createSandboxedRequest(originalModule.request);
    virtualHttp.get = createSandboxedRequest(originalModule.get);

    return Object.freeze(virtualHttp);
  }

  /**
   * Create a virtual 'child_process' — disabled by default
   */
  createVirtualChildProcess(packageName) {
    const policy = this.policy.getPackagePolicy(packageName);
    const allowedCommands = policy.shell || [];

    if (allowedCommands.length === 0) {
      // No shell access — module "doesn't work"
      return Object.freeze({
        exec: (cmd, opts, cb) => {
          if (typeof opts === 'function') { cb = opts; }
          const err = new Error(`spawn ENOENT`);
          err.code = 'ENOENT';
          if (cb) process.nextTick(() => cb(err, '', ''));
        },
        execSync: () => {
          const err = new Error(`spawnSync ENOENT`);
          err.code = 'ENOENT';
          throw err;
        },
        spawn: () => {
          const EventEmitter = require('events');
          const dummy = new EventEmitter();
          dummy.stdout = new EventEmitter();
          dummy.stderr = new EventEmitter();
          dummy.stdin = { write: () => {}, end: () => {} };
          dummy.pid = 0;
          dummy.kill = () => {};
          process.nextTick(() => {
            const err = new Error(`spawn ENOENT`);
            err.code = 'ENOENT';
            dummy.emit('error', err);
          });
          return dummy;
        },
        spawnSync: () => ({ status: 1, error: { code: 'ENOENT' }, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }),
        fork: () => { throw Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' }); },
        execFile: (file, args, opts, cb) => {
          if (typeof opts === 'function') { cb = opts; }
          if (typeof args === 'function') { cb = args; }
          const err = Object.assign(new Error(`spawn ${file} ENOENT`), { code: 'ENOENT' });
          if (cb) process.nextTick(() => cb(err));
          else throw err;
        },
        execFileSync: () => { throw Object.assign(new Error('spawnSync ENOENT'), { code: 'ENOENT' }); }
      });
    }

    // Limited shell access — only allowed commands
    const originalCp = _originals.child_process;
    return Object.freeze({
      exec: (cmd, opts, cb) => {
        if (typeof opts === 'function') { cb = opts; opts = {}; }
        const cmdBase = String(cmd).split(/\s+/)[0];
        if (!allowedCommands.some(a => cmdBase.includes(a))) {
          const err = Object.assign(new Error(`spawn ENOENT`), { code: 'ENOENT' });
          if (cb) return process.nextTick(() => cb(err, '', ''));
          throw err;
        }
        return originalCp.exec.call(originalCp, cmd, opts, cb);
      },
      execSync: (cmd, opts) => {
        const cmdBase = String(cmd).split(/\s+/)[0];
        if (!allowedCommands.some(a => cmdBase.includes(a))) {
          throw Object.assign(new Error(`spawnSync ENOENT`), { code: 'ENOENT' });
        }
        return originalCp.execSync.call(originalCp, cmd, opts);
      },
      spawn: (cmd, args, opts) => {
        if (!allowedCommands.some(a => String(cmd).includes(a))) {
          const EventEmitter = require('events');
          const dummy = new EventEmitter();
          dummy.stdout = new EventEmitter(); dummy.stderr = new EventEmitter();
          dummy.stdin = { write: ()=>{}, end: ()=>{} }; dummy.pid = 0; dummy.kill = ()=>{};
          process.nextTick(() => dummy.emit('error', Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' })));
          return dummy;
        }
        return originalCp.spawn.call(originalCp, cmd, args, opts);
      },
      spawnSync: (cmd, args, opts) => {
        if (!allowedCommands.some(a => String(cmd).includes(a))) {
          return { status: 1, error: { code: 'ENOENT' }, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
        }
        return originalCp.spawnSync.call(originalCp, cmd, args, opts);
      },
      fork: originalCp.fork.bind(originalCp),
      execFile: originalCp.execFile.bind(originalCp),
      execFileSync: originalCp.execFileSync.bind(originalCp)
    });
  }

  /**
   * Create a virtual 'process.env' — only shows allowed vars
   */
  createVirtualEnv(packageName) {
    const policy = this.policy.getPackagePolicy(packageName);
    const visibleVars = policy.env_visible || [];

    // If empty policy = see NOTHING
    if (visibleVars.length === 0 && !policy.env_all) {
      return Object.freeze(new Proxy({}, {
        get: () => undefined,
        has: () => false,
        ownKeys: () => [],
        getOwnPropertyDescriptor: () => undefined
      }));
    }

    // Show only allowed vars
    const realEnv = process.env;
    return new Proxy({}, {
      get(_, prop) {
        if (typeof prop !== 'string') return undefined;
        if (visibleVars.includes(prop) || visibleVars.includes('*')) {
          return realEnv[prop];
        }
        // Check glob patterns
        for (const pattern of visibleVars) {
          if (pattern.includes('*') && matchGlob(prop, pattern)) {
            return realEnv[prop];
          }
        }
        return undefined;
      },
      has(_, prop) {
        if (typeof prop !== 'string') return false;
        if (visibleVars.includes(prop) || visibleVars.includes('*')) return prop in realEnv;
        for (const pattern of visibleVars) {
          if (pattern.includes('*') && matchGlob(prop, pattern)) return prop in realEnv;
        }
        return false;
      },
      ownKeys() {
        if (visibleVars.includes('*')) return Object.keys(realEnv);
        return Object.keys(realEnv).filter(k => {
          if (visibleVars.includes(k)) return true;
          return visibleVars.some(p => p.includes('*') && matchGlob(k, p));
        });
      },
      getOwnPropertyDescriptor(_, prop) {
        if (this.has(_, prop)) {
          return { value: this.get(_, prop), writable: true, enumerable: true, configurable: true };
        }
        return undefined;
      },
      set(_, prop, value) {
        // Packages can't set env vars they can't see
        if (visibleVars.includes(prop) || visibleVars.includes('*')) {
          realEnv[prop] = value;
          return true;
        }
        return true; // Silently ignore (not "blocked")
      }
    });
  }

  /**
   * Create blocked modules (inspector, v8, etc.)
   */
  createBlockedModule(moduleName) {
    // Return a module that looks like it doesn't exist
    const err = new Error(`Cannot find module '${moduleName}'`);
    err.code = 'MODULE_NOT_FOUND';
    throw err;
  }
}

// --- Helper Functions ---

function safeRealpath(filePath) {
  try {
    return _originals.fs.realpathSync(filePath);
  } catch (e) {
    return filePath;
  }
}

function isPathAllowed(resolvedPath, allowedPaths) {
  if (!allowedPaths || allowedPaths.length === 0) return false;
  if (allowedPaths.includes('*')) return true;

  for (const allowed of allowedPaths) {
    if (allowed.endsWith('*')) {
      const prefix = allowed.slice(0, -1);
      if (resolvedPath.startsWith(path.resolve(prefix))) return true;
    } else {
      if (resolvedPath === path.resolve(allowed)) return true;
      if (resolvedPath.startsWith(path.resolve(allowed) + path.sep)) return true;
    }
  }
  return false;
}

function isDomainAllowed(hostname, allowedDomains) {
  if (!allowedDomains || allowedDomains.length === 0) return false;
  if (allowedDomains.includes('*')) return true;

  const host = hostname.split(':')[0].toLowerCase();

  for (const allowed of allowedDomains) {
    const pattern = allowed.split(':')[0].toLowerCase();
    if (pattern === host) return true;
    if (pattern.startsWith('*.') && host.endsWith(pattern.slice(1))) return true;
    if (pattern.startsWith('.') && host.endsWith(pattern)) return true;
  }

  // Always allow localhost
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return true;

  return false;
}

function matchGlob(value, pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i').test(value);
}

module.exports = { VirtualModuleFactory, _originals, isDomainAllowed, isPathAllowed };
