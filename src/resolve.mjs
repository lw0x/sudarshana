'use strict';

/**
 * SUDARSHANA — ESM Loader Hook
 * 
 * The CJS hook intercepts require(). This intercepts import.
 * Same philosophy: per-package sandboxing, invisible, natural errors.
 * 
 * Usage:
 *   Node 20+:  node --import ./src/esm-loader.mjs app.mjs
 *   Node 18:   node --experimental-loader ./src/esm-loader.mjs app.mjs
 *   Via CLI:   sudarshana run -- node app.mjs   (auto-detects)
 * 
 * How it works:
 *   1. resolve() — intercepts every import specifier
 *   2. load() — wraps module source code with sandbox injection
 *   3. Each ESM module gets wrapped process.env, fetch, fs via import rewrites
 */

import { readFileSync, existsSync } from 'fs';
import { resolve as pathResolve, dirname, basename, sep } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

// ─── Config Loading ─────────────────────────────────────────────
let config = null;
let policies = {};

function loadConfig() {
  if (config) return config;
  
  // Walk up from CWD looking for .sudarshana.json or sudarshana.config.json
  let dir = process.cwd();
  const configNames = ['.sudarshana.json', 'sudarshana.config.json'];
  
  while (dir !== dirname(dir)) {
    for (const name of configNames) {
      const candidate = pathResolve(dir, name);
      if (existsSync(candidate)) {
        try {
          config = JSON.parse(readFileSync(candidate, 'utf8'));
          policies = config.policies || {};
          return config;
        } catch (e) { /* continue searching */ }
      }
    }
    dir = dirname(dir);
  }
  
  // No config found — use defaults (warn but don't crash)
  config = { mode: 'monitor', policies: {} };
  policies = {};
  return config;
}

// ─── Package Attribution ────────────────────────────────────────
function getPackageFromUrl(url) {
  if (!url || !url.startsWith('file://')) return '_application_';
  
  const filePath = fileURLToPath(url);
  const nmIndex = filePath.lastIndexOf(`${sep}node_modules${sep}`);
  
  if (nmIndex === -1) return '_application_';
  
  const afterNm = filePath.substring(nmIndex + `${sep}node_modules${sep}`.length);
  
  // Handle scoped packages (@org/pkg)
  if (afterNm.startsWith('@')) {
    const parts = afterNm.split(sep);
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : afterNm.split(sep)[0];
  }
  
  return afterNm.split(sep)[0];
}

function getPolicyForPackage(packageName) {
  loadConfig();
  
  if (policies[packageName]) return policies[packageName];
  
  // Check if it matches any glob pattern in policies
  for (const [pattern, policy] of Object.entries(policies)) {
    if (pattern.endsWith('*')) {
      const prefix = pattern.slice(0, -1);
      if (packageName.startsWith(prefix)) return policy;
    }
  }
  
  // Default: deny everything (zero trust)
  return {
    trust_level: 'untrusted',
    env_visible: [],
    fs_read: [],
    fs_write: [],
    network: [],
    shell: []
  };
}

// ─── Virtual Environment Generator ─────────────────────────────
function generateEnvWrapper(policy) {
  const allowed = policy.env_visible || [];
  
  if (allowed.includes('*')) {
    return ''; // full access — no wrapping needed
  }
  
  const allowedJson = JSON.stringify(allowed);
  
  return `
// ═══ Sudarshana: Virtual Environment ═══
const __sudarshana_allowed_env = new Set(${allowedJson});
const __sudarshana_real_env = process.env;
const __sudarshana_honeypots = {
  AWS_SECRET_ACCESS_KEY: ['TRAP', Date.now().toString(36), 'x0FAKE'].join('_'),
  GITHUB_TOKEN: ['TRAP', Date.now().toString(36), 'x1FAKE'].join('_'),
  DATABASE_URL: 'trap://127.0.0.1:0/honeypot_' + Date.now().toString(36),
  STRIPE_SECRET_KEY: ['TRAP', Date.now().toString(36), 'x2FAKE'].join('_')
};

const __sudarshana_virtual_env = new Proxy(__sudarshana_real_env, {
  get(target, prop) {
    if (typeof prop !== 'string') return Reflect.get(target, prop);
    
    // Honeypot check
    if (prop in __sudarshana_honeypots && !__sudarshana_allowed_env.has(prop)) {
      // ALERT: Package accessing honeypot credential
      process.emit('sudarshana:alert', {
        type: 'HONEYPOT_ACCESS',
        severity: 'CRITICAL',
        key: prop,
        timestamp: Date.now()
      });
      return __sudarshana_honeypots[prop];
    }
    
    // Policy check
    if (__sudarshana_allowed_env.has('*') || __sudarshana_allowed_env.has(prop)) {
      return target[prop];
    }
    return undefined;
  },
  has(target, prop) {
    if (__sudarshana_allowed_env.has('*')) return prop in target;
    return __sudarshana_allowed_env.has(prop) && prop in target;
  },
  ownKeys(target) {
    if (__sudarshana_allowed_env.has('*')) return Reflect.ownKeys(target);
    return Reflect.ownKeys(target).filter(k => __sudarshana_allowed_env.has(k));
  },
  getOwnPropertyDescriptor(target, prop) {
    if (!__sudarshana_allowed_env.has('*') && !__sudarshana_allowed_env.has(prop)) return undefined;
    return Object.getOwnPropertyDescriptor(target, prop);
  }
});

// Replace process.env for this module scope
const process = new Proxy(globalThis.process, {
  get(target, prop) {
    if (prop === 'env') return __sudarshana_virtual_env;
    return Reflect.get(target, prop);
  }
});
// ═══ End Sudarshana wrapper ═══
`;
}

// ─── Network Restriction Generator ─────────────────────────────
function generateNetworkWrapper(policy) {
  const allowed = policy.network || [];
  
  if (allowed.includes('*')) return '';
  if (allowed.length === 0) {
    // No network access — override fetch
    return `
// ═══ Sudarshana: Network Denied ═══
const fetch = async (url) => {
  throw new TypeError('fetch failed');
};
// ═══ End network wrapper ═══
`;
  }
  
  const allowedJson = JSON.stringify(allowed);
  return `
// ═══ Sudarshana: Network Policy ═══
const __sudarshana_allowed_domains = ${allowedJson};
const __sudarshana_original_fetch = globalThis.fetch;

function __sudarshana_isDomainAllowed(urlString) {
  try {
    const url = new URL(urlString);
    const domain = url.hostname;
    return __sudarshana_allowed_domains.some(pattern => {
      if (pattern.startsWith('*.')) {
        const suffix = pattern.slice(2);
        return domain === suffix || domain.endsWith('.' + suffix);
      }
      return domain === pattern || pattern === domain + ':' + url.port;
    });
  } catch { return false; }
}

const fetch = async (url, opts) => {
  const urlStr = typeof url === 'string' ? url : url.url || url.href || String(url);
  if (!__sudarshana_isDomainAllowed(urlStr)) {
    throw new TypeError('fetch failed');
  }
  return __sudarshana_original_fetch(url, opts);
};
// ═══ End network wrapper ═══
`;
}

// ─── Shell Restriction Generator ────────────────────────────────
function generateShellWrapper(policy) {
  const allowed = policy.shell || [];
  
  if (allowed.includes('*')) return '';
  
  // For ESM, we override the child_process import at resolve level
  // This wrapper catches dynamic import('child_process')
  if (allowed.length === 0) {
    return `
// ═══ Sudarshana: Shell Denied ═══
// child_process import blocked at resolve level
// ═══ End shell wrapper ═══
`;
  }
  return '';
}

// ─── Behavioral Tracking ────────────────────────────────────────
function generateBehavioralTracker(packageName) {
  return `
// ═══ Sudarshana: Behavioral Tracking ═══
const __sudarshana_pkg = ${JSON.stringify(packageName)};
// Events are emitted to process for the main-thread engine to correlate
// ═══ End behavioral tracker ═══
`;
}

// ═══════════════════════════════════════════════════════════════════
//  ESM LOADER HOOKS
// ═══════════════════════════════════════════════════════════════════

/**
 * resolve() — Controls which modules a package can import
 * 
 * We block specific built-in modules based on policy:
 * - No shell policy → can't import 'child_process'
 * - No network policy → can't import 'net', 'tls', 'http', 'https', 'dgram'
 * - No fs policy → can't import 'fs', 'fs/promises'
 */
export async function resolve(specifier, context, nextResolve) {
  loadConfig();
  
  const parentPackage = getPackageFromUrl(context.parentURL);
  const policy = getPolicyForPackage(parentPackage);
  
  // Block built-in modules based on policy
  const networkModules = ['net', 'tls', 'http', 'https', 'http2', 'dgram', 'dns'];
  const fsModules = ['fs', 'fs/promises'];
  const shellModules = ['child_process'];
  
  // If package has no network access and tries to import network modules
  if ((!policy.network || policy.network.length === 0) && networkModules.includes(specifier)) {
    if (policy.trust_level !== 'system') {
      // Return a virtual empty module instead of blocking entirely
      // This prevents crash but removes functionality
      return {
        url: `sudarshana:blocked:${specifier}:${parentPackage}`,
        shortCircuit: true
      };
    }
  }
  
  // If package has no shell access
  if ((!policy.shell || policy.shell.length === 0) && shellModules.includes(specifier)) {
    if (policy.trust_level !== 'system') {
      return {
        url: `sudarshana:blocked:${specifier}:${parentPackage}`,
        shortCircuit: true
      };
    }
  }
  
  // If package has no fs access  
  if ((!policy.fs_read || policy.fs_read.length === 0) && fsModules.includes(specifier)) {
    if (policy.trust_level !== 'system') {
      return {
        url: `sudarshana:blocked:${specifier}:${parentPackage}`,
        shortCircuit: true
      };
    }
  }
  
  return nextResolve(specifier, context);
}

/**
 * load() — Wraps module source with sandbox code
 * 
 * For every module loaded from node_modules, we prepend:
 * - Virtual process.env (only sees allowed vars)
 * - Virtual fetch (only reaches allowed domains)
 * - Behavioral tracking hooks
 */
export async function load(url, context, nextLoad) {
  // Handle blocked modules — return empty stubs
  if (url.startsWith('sudarshana:blocked:')) {
    const parts = url.split(':');
    const blockedModule = parts[2];
    
    // Return a stub that throws natural errors
    const stubs = {
      'child_process': `
        export const exec = () => { throw new Error('spawn ENOENT'); };
        export const execSync = () => { throw new Error('spawn ENOENT'); };
        export const spawn = () => { throw new Error('spawn ENOENT'); };
        export const fork = () => { throw new Error('spawn ENOENT'); };
        export default { exec, execSync, spawn, fork };
      `,
      'net': `
        export const connect = () => { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }); };
        export const createConnection = connect;
        export const createServer = () => ({ listen: () => {} });
        export default { connect, createConnection, createServer };
      `,
      'http': `
        export const request = () => { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }); };
        export const get = request;
        export const createServer = () => ({ listen: () => {} });
        export default { request, get, createServer };
      `,
      'https': `
        export const request = () => { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }); };
        export const get = request;
        export default { request, get };
      `,
      'dns': `
        export const resolve = (h, cb) => cb(Object.assign(new Error('queryA ENOTFOUND ' + h), { code: 'ENOTFOUND' }));
        export const lookup = (h, cb) => cb(Object.assign(new Error('getaddrinfo ENOTFOUND ' + h), { code: 'ENOTFOUND' }));
        export default { resolve, lookup };
      `,
      'fs': `
        const err = (p) => Object.assign(new Error("ENOENT: no such file or directory, open '" + p + "'"), { code: 'ENOENT', errno: -2 });
        export const readFileSync = (p) => { throw err(p); };
        export const readFile = (p, cb) => cb(err(p));
        export const existsSync = () => false;
        export const statSync = (p) => { throw err(p); };
        export default { readFileSync, readFile, existsSync, statSync };
      `,
      'fs/promises': `
        const err = (p) => Object.assign(new Error("ENOENT: no such file or directory, open '" + p + "'"), { code: 'ENOENT', errno: -2 });
        export const readFile = async (p) => { throw err(p); };
        export const stat = async (p) => { throw err(p); };
        export const access = async (p) => { throw err(p); };
        export default { readFile, stat, access };
      `
    };
    
    const source = stubs[blockedModule] || `export default {};`;
    
    return {
      format: 'module',
      source,
      shortCircuit: true
    };
  }
  
  // Load the real module
  const result = await nextLoad(url, context);
  
  // Only wrap modules from node_modules that have source code
  if (!url.includes('node_modules') || result.format !== 'module' || !result.source) {
    return result;
  }
  
  // Identify which package this belongs to
  const packageName = getPackageFromUrl(url);
  const policy = getPolicyForPackage(packageName);
  
  // System-level trust = no wrapping
  if (policy.trust_level === 'system') return result;
  
  // Generate wrapper code
  const envWrapper = generateEnvWrapper(policy);
  const netWrapper = generateNetworkWrapper(policy);
  const shellWrapper = generateShellWrapper(policy);
  const tracker = generateBehavioralTracker(packageName);
  
  // Prepend wrappers to module source
  const originalSource = typeof result.source === 'string' 
    ? result.source 
    : Buffer.from(result.source).toString('utf8');
  
  const wrappedSource = `${tracker}${envWrapper}${netWrapper}${shellWrapper}${originalSource}`;
  
  return {
    ...result,
    source: wrappedSource
  };
}

/**
 * initialize() — Called once when loader is registered (Node 20+ register API)
 */
export function initialize(data) {
  loadConfig();
  
  if (config && config.mode !== 'silent') {
    // Silent initialization — don't reveal ourselves
  }
}
