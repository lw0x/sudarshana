'use strict';

/**
 * SUDARSHANA v2.0 — POLICY ENGINE
 * 
 * Zero Trust: Every package gets NOTHING by default.
 * Access must be explicitly granted.
 * 
 * Policies define what each package can:
 * - SEE (env vars, file paths)
 * - REACH (network domains)
 * - EXECUTE (shell commands)
 * - USE (which Node.js modules are available)
 * 
 * The philosophy: "deny unless explicitly proven safe"
 */

const path = require('path');
const crypto = require('crypto');

const SENSITIVE_ENV_PATTERNS = [
  /AWS_/i, /SECRET/i, /TOKEN/i, /PASSWORD/i, /KEY/i, /PRIVATE/i,
  /DATABASE_URL/i, /DB_/i, /REDIS_/i, /MONGO/i, /MYSQL/i,
  /API_KEY/i, /STRIPE/i, /TWILIO/i, /SENDGRID/i, /AUTH/i,
  /GITHUB_TOKEN/i, /NPM_TOKEN/i, /CI_TOKEN/i, /DEPLOY/i
];

const SENSITIVE_PATHS = [
  '/etc/passwd', '/etc/shadow', '/etc/hosts',
  '.env', '.env.local', '.env.production', '.env.development',
  'id_rsa', 'id_ed25519', 'id_dsa', '.pem', '.key',
  '.aws/credentials', '.aws/config',
  '.ssh/', '.gnupg/', '.npmrc', '.netrc',
  '/proc/self/environ', '/proc/1/environ',
  '/var/run/docker.sock', '/run/secrets/',
  '/var/run/secrets/kubernetes.io/',
  '~/.kube/config', '/etc/kubernetes/',
  '.git/config', '.gitconfig'
];

const DEFAULT_POLICY = Object.freeze({
  env_visible: [],          // See NO env vars
  env_all: false,           // Not even NODE_ENV
  fs_read: [],              // Read NO files outside own package
  fs_write: [],             // Write NOTHING
  network: [],              // No network access
  shell: [],                // No shell execution
  modules_blocked: ['inspector', 'v8', 'vm', 'worker_threads'],
  modules_available: ['path', 'url', 'querystring', 'util', 'buffer', 'stream', 'events', 'string_decoder', 'punycode', 'assert'],
  allow_native_addons: false,
  allow_wasm: false,
  trust_level: 'untrusted'  // untrusted | limited | trusted | system
});

/**
 * Well-known package presets — community-vetted permissions
 * These define what popular packages ACTUALLY need to function
 */
const KNOWN_PACKAGE_POLICIES = {
  // === PURE COMPUTE (zero capabilities needed) ===
  'lodash': { trust_level: 'trusted', env_visible: [], network: [], fs_read: [], shell: [] },
  'underscore': { trust_level: 'trusted', env_visible: [], network: [], fs_read: [], shell: [] },
  'ramda': { trust_level: 'trusted', env_visible: [], network: [], fs_read: [], shell: [] },
  'moment': { trust_level: 'trusted', env_visible: ['TZ'], network: [], fs_read: [], shell: [] },
  'dayjs': { trust_level: 'trusted', env_visible: ['TZ'], network: [], fs_read: [], shell: [] },
  'uuid': { trust_level: 'trusted', env_visible: [], network: [], fs_read: [], shell: [] },
  'validator': { trust_level: 'trusted', env_visible: [], network: [], fs_read: [], shell: [] },
  'zod': { trust_level: 'trusted', env_visible: [], network: [], fs_read: [], shell: [] },
  'yup': { trust_level: 'trusted', env_visible: [], network: [], fs_read: [], shell: [] },
  'ajv': { trust_level: 'trusted', env_visible: [], network: [], fs_read: [], shell: [] },

  // === NEED ENV ONLY ===
  'dotenv': { trust_level: 'limited', env_visible: ['*'], fs_read: ['.env*'], network: [], shell: [] },
  'config': { trust_level: 'limited', env_visible: ['NODE_ENV', 'NODE_CONFIG_*'], fs_read: ['config/*'], network: [], shell: [] },

  // === NEED NETWORK ===
  'axios': { trust_level: 'limited', env_visible: ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'], network: ['DECLARED_IN_CONFIG'], fs_read: [], shell: [] },
  'node-fetch': { trust_level: 'limited', env_visible: ['HTTP_PROXY', 'HTTPS_PROXY'], network: ['DECLARED_IN_CONFIG'], fs_read: [], shell: [] },
  'got': { trust_level: 'limited', env_visible: ['HTTP_PROXY', 'HTTPS_PROXY'], network: ['DECLARED_IN_CONFIG'], fs_read: [], shell: [] },

  // === NEED FS ===
  'fs-extra': { trust_level: 'limited', env_visible: [], network: [], fs_read: ['PROJECT_ROOT/*'], fs_write: ['PROJECT_ROOT/*'], shell: [] },
  'glob': { trust_level: 'limited', env_visible: [], network: [], fs_read: ['PROJECT_ROOT/*'], shell: [] },
  'chokidar': { trust_level: 'limited', env_visible: [], network: [], fs_read: ['PROJECT_ROOT/*'], shell: [] },

  // === NEED SHELL (dangerous — restricted by default) ===
  'cross-spawn': { trust_level: 'limited', env_visible: ['PATH', 'PATHEXT', 'ComSpec'], network: [], fs_read: [], shell: ['DECLARED_IN_CONFIG'] },
  'execa': { trust_level: 'limited', env_visible: ['PATH', 'PATHEXT'], network: [], fs_read: [], shell: ['DECLARED_IN_CONFIG'] },

  // === FRAMEWORK (needs more, but still bounded) ===
  'express': { trust_level: 'trusted', env_visible: ['NODE_ENV', 'PORT', 'HOST'], network: ['localhost:*'], fs_read: ['PROJECT_ROOT/views/*', 'PROJECT_ROOT/public/*', 'PROJECT_ROOT/static/*'], shell: [] },
  'fastify': { trust_level: 'trusted', env_visible: ['NODE_ENV', 'PORT', 'HOST'], network: ['localhost:*'], fs_read: ['PROJECT_ROOT/views/*', 'PROJECT_ROOT/public/*'], shell: [] },
  'koa': { trust_level: 'trusted', env_visible: ['NODE_ENV', 'PORT'], network: ['localhost:*'], fs_read: [], shell: [] },

  // === EXPLICITLY DANGEROUS (always sandboxed) ===
  'puppeteer': { trust_level: 'limited', env_visible: ['PUPPETEER_*'], network: ['DECLARED_IN_CONFIG'], fs_read: [], shell: [], modules_blocked: ['inspector'] },
  'sharp': { trust_level: 'limited', env_visible: [], network: [], fs_read: ['DECLARED_IN_CONFIG'], shell: [], allow_native_addons: true },
  'nodemailer': { trust_level: 'limited', env_visible: [], network: ['DECLARED_IN_CONFIG'], fs_read: [], shell: [] },
};

class PolicyEngine {
  constructor(config = {}) {
    this.projectRoot = config.projectRoot || process.cwd();
    this.customPolicies = config.policies || {};
    this.configHash = null;
    this.configPath = config.configPath || null;
    this._validateAndSign(config);
  }

  /**
   * Get the effective policy for a package
   * Priority: custom config > known presets > default (deny all)
   */
  getPackagePolicy(packageName) {
    // 1. User-defined custom policy (highest priority)
    if (this.customPolicies[packageName]) {
      return this._resolvePolicy(this.customPolicies[packageName]);
    }

    // 2. Known package preset
    const baseName = packageName.split('/').pop(); // Handle scoped packages
    if (KNOWN_PACKAGE_POLICIES[baseName]) {
      return this._resolvePolicy(KNOWN_PACKAGE_POLICIES[baseName]);
    }

    // 3. Match by scope
    if (packageName.startsWith('@')) {
      const scope = packageName.split('/')[0];
      if (this.customPolicies[scope + '/*']) {
        return this._resolvePolicy(this.customPolicies[scope + '/*']);
      }
    }

    // 4. Default: DENY EVERYTHING
    return this._resolvePolicy(DEFAULT_POLICY);
  }

  /**
   * Check if an env var is sensitive
   */
  isSensitiveEnv(varName) {
    return SENSITIVE_ENV_PATTERNS.some(pattern => pattern.test(varName));
  }

  /**
   * Check if a path is sensitive
   */
  isSensitivePath(filePath) {
    const normalized = filePath.replace(/\\/g, '/').toLowerCase();
    return SENSITIVE_PATHS.some(sensitive => normalized.includes(sensitive.toLowerCase()));
  }

  /**
   * Resolve placeholders in policy values
   */
  _resolvePolicy(policy) {
    const resolved = { ...DEFAULT_POLICY, ...policy };

    // Resolve PROJECT_ROOT
    if (resolved.fs_read) {
      resolved.fs_read = resolved.fs_read.map(p => 
        p.replace('PROJECT_ROOT', this.projectRoot)
      );
    }
    if (resolved.fs_write) {
      resolved.fs_write = resolved.fs_write.map(p =>
        p.replace('PROJECT_ROOT', this.projectRoot)
      );
    }

    return Object.freeze(resolved);
  }

  /**
   * Validate config integrity (prevent tampering)
   */
  _validateAndSign(config) {
    if (config._signature) {
      // Verify existing signature
      const content = JSON.stringify({ ...config, _signature: undefined });
      const expected = crypto.createHash('sha256').update(content).digest('hex');
      if (expected !== config._signature) {
        throw new Error('[SUDARSHANA] Config integrity check FAILED! File may have been tampered.');
      }
    }
    this.configHash = crypto.createHash('sha256')
      .update(JSON.stringify(this.customPolicies))
      .digest('hex');
  }

  /**
   * Generate a config signature for tamper detection
   */
  signConfig(config) {
    const content = JSON.stringify(config);
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Classify an unknown package's risk based on its dependencies
   */
  classifyPackage(packageJson) {
    const risk = { score: 0, reasons: [] };

    // Check for dangerous capabilities
    if (packageJson.scripts) {
      if (packageJson.scripts.preinstall) { risk.score += 30; risk.reasons.push('preinstall script'); }
      if (packageJson.scripts.postinstall) { risk.score += 20; risk.reasons.push('postinstall script'); }
      if (packageJson.scripts.install) { risk.score += 20; risk.reasons.push('install script'); }
    }

    // Native addons
    if (packageJson.gypfile || (packageJson.scripts && packageJson.scripts.install && packageJson.scripts.install.includes('node-gyp'))) {
      risk.score += 25;
      risk.reasons.push('native addon (node-gyp)');
    }

    // Binary deps
    if (packageJson.bin) { risk.score += 10; risk.reasons.push('ships binary'); }

    // No repository = suspicious
    if (!packageJson.repository) { risk.score += 15; risk.reasons.push('no repository URL'); }

    // Very new package
    if (packageJson._time && packageJson._time.created) {
      const created = new Date(packageJson._time.created);
      const daysOld = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);
      if (daysOld < 7) { risk.score += 20; risk.reasons.push('less than 7 days old'); }
    }

    return risk;
  }

  /**
   * Auto-generate policy suggestion based on package analysis
   */
  suggestPolicy(packageName, packageJson) {
    const risk = this.classifyPackage(packageJson);
    const deps = Object.keys(packageJson.dependencies || {});
    
    const suggestion = { ...DEFAULT_POLICY };

    // If it depends on HTTP libraries → likely needs network
    const httpDeps = deps.filter(d => ['axios', 'node-fetch', 'got', 'request', 'undici'].includes(d));
    if (httpDeps.length > 0) {
      suggestion.network = ['NEEDS_DECLARATION']; // User must specify domains
    }

    // If it depends on fs libraries → likely needs file access
    const fsDeps = deps.filter(d => ['fs-extra', 'glob', 'chokidar', 'graceful-fs'].includes(d));
    if (fsDeps.length > 0) {
      suggestion.fs_read = ['PROJECT_ROOT/*'];
    }

    return { suggestion, risk, needsReview: risk.score > 20 };
  }
}

module.exports = { PolicyEngine, DEFAULT_POLICY, KNOWN_PACKAGE_POLICIES, SENSITIVE_PATHS, SENSITIVE_ENV_PATTERNS };
