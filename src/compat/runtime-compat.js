'use strict';

/**
 * SUDARSHANA — RUNTIME COMPATIBILITY LAYER
 * 
 * "The disc protects without breaking. Ever."
 * 
 * This module ensures Sudarshana works in ANY real-world project:
 * - TypeScript (ts-node, tsx, esbuild-register)
 * - Bundlers (Webpack, Vite, esbuild, Rollup)
 * - Monorepos (Nx, Turborepo, Lerna, pnpm workspaces)
 * - Windows paths (backslash normalization)
 * - Serverless (AWS Lambda, Vercel, Cloudflare Workers)
 * - ESM + CJS mixed projects
 * - Circular dependencies
 * - Dynamic imports (import())
 * 
 * GOLDEN RULE: If Sudarshana can't handle something → PASS THROUGH.
 * Never crash. Never block legitimate code. Fail open, log the gap.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');

// ═══════════════════════════════════════════════════════════════
// PLATFORM DETECTION
// ═══════════════════════════════════════════════════════════════

const PLATFORM = {
  isWindows: os.platform() === 'win32',
  isMac: os.platform() === 'darwin',
  isLinux: os.platform() === 'linux',
  sep: path.sep,
  nodeVersion: parseInt(process.version.slice(1)),
  nodeMajor: parseInt(process.version.split('.')[0].slice(1)),
  nodeMinor: parseInt(process.version.split('.')[1]),
};

// ═══════════════════════════════════════════════════════════════
// PATH NORMALIZATION (Windows ↔ Unix)
// ═══════════════════════════════════════════════════════════════

/**
 * Normalize any path to forward slashes (internal representation)
 * Sudarshana uses forward slashes internally, converts to OS-specific only at boundaries
 */
function normalizePath(filePath) {
  if (!filePath || typeof filePath !== 'string') return filePath;
  // Convert backslashes to forward slashes
  let normalized = filePath.replace(/\\/g, '/');
  // Remove trailing slash
  if (normalized.endsWith('/') && normalized.length > 1) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

/**
 * Convert internal path back to OS-native path
 */
function toOsPath(filePath) {
  if (!filePath) return filePath;
  if (PLATFORM.isWindows) {
    return filePath.replace(/\//g, '\\');
  }
  return filePath;
}

/**
 * Check if a path matches a policy pattern (cross-platform)
 */
function pathMatchesPolicy(filePath, patterns) {
  if (!patterns || patterns.length === 0) return false;
  if (patterns.includes('*')) return true;

  const normalizedFile = normalizePath(filePath);

  for (const pattern of patterns) {
    const normalizedPattern = normalizePath(pattern);

    // Exact match
    if (normalizedFile === normalizedPattern) return true;

    // Wildcard match: ./src/* matches ./src/anything
    if (normalizedPattern.endsWith('/*')) {
      const base = normalizedPattern.slice(0, -2);
      if (normalizedFile.startsWith(base + '/') || normalizedFile === base) return true;
    }

    // Prefix match: ./node_modules/express matches ./node_modules/express/index.js
    if (normalizedFile.startsWith(normalizedPattern + '/')) return true;
    if (normalizedFile.startsWith(normalizedPattern)) return true;
  }

  return false;
}

// ═══════════════════════════════════════════════════════════════
// ENVIRONMENT DETECTION
// ═══════════════════════════════════════════════════════════════

/**
 * Detect the project environment and compilation chain
 */
function detectEnvironment(projectRoot) {
  const env = {
    typescript: false,
    tsRunner: null,     // 'ts-node' | 'tsx' | 'esbuild-register' | 'swc-register'
    bundler: null,      // 'webpack' | 'vite' | 'esbuild' | 'rollup' | 'parcel'
    monorepo: null,     // 'nx' | 'turborepo' | 'lerna' | 'pnpm-workspace'
    serverless: null,   // 'lambda' | 'vercel' | 'cloudflare'
    moduleType: 'cjs',  // 'cjs' | 'esm' | 'mixed'
    packageManager: 'npm', // 'npm' | 'yarn' | 'pnpm'
  };

  const pkgJsonPath = path.join(projectRoot, 'package.json');
  if (!fs.existsSync(pkgJsonPath)) return env;

  try {
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));

    // TypeScript detection
    if (fs.existsSync(path.join(projectRoot, 'tsconfig.json'))) {
      env.typescript = true;
    }
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (allDeps['ts-node']) env.tsRunner = 'ts-node';
    else if (allDeps['tsx']) env.tsRunner = 'tsx';
    else if (allDeps['esbuild-register']) env.tsRunner = 'esbuild-register';
    else if (allDeps['@swc/register']) env.tsRunner = 'swc-register';

    // Bundler detection
    if (allDeps['webpack'] || fs.existsSync(path.join(projectRoot, 'webpack.config.js'))) env.bundler = 'webpack';
    else if (allDeps['vite'] || fs.existsSync(path.join(projectRoot, 'vite.config.ts')) || fs.existsSync(path.join(projectRoot, 'vite.config.js'))) env.bundler = 'vite';
    else if (allDeps['esbuild']) env.bundler = 'esbuild';
    else if (allDeps['rollup']) env.bundler = 'rollup';
    else if (allDeps['parcel']) env.bundler = 'parcel';

    // Monorepo detection
    if (fs.existsSync(path.join(projectRoot, 'nx.json'))) env.monorepo = 'nx';
    else if (fs.existsSync(path.join(projectRoot, 'turbo.json'))) env.monorepo = 'turborepo';
    else if (fs.existsSync(path.join(projectRoot, 'lerna.json'))) env.monorepo = 'lerna';
    else if (fs.existsSync(path.join(projectRoot, 'pnpm-workspace.yaml'))) env.monorepo = 'pnpm-workspace';
    else if (pkg.workspaces) env.monorepo = 'yarn-workspaces';

    // Serverless detection
    if (allDeps['@aws-sdk/client-lambda'] || fs.existsSync(path.join(projectRoot, 'serverless.yml'))) env.serverless = 'lambda';
    else if (fs.existsSync(path.join(projectRoot, 'vercel.json'))) env.serverless = 'vercel';
    else if (fs.existsSync(path.join(projectRoot, 'wrangler.toml'))) env.serverless = 'cloudflare';

    // Module type
    if (pkg.type === 'module') env.moduleType = 'esm';
    else if (pkg.type === 'commonjs' || !pkg.type) env.moduleType = 'cjs';
    // Check if there's a mix (.mjs + .cjs files)
    const hasMjs = fs.readdirSync(projectRoot).some(f => f.endsWith('.mjs'));
    const hasCjs = fs.readdirSync(projectRoot).some(f => f.endsWith('.cjs'));
    if (hasMjs && hasCjs) env.moduleType = 'mixed';

    // Package manager
    if (fs.existsSync(path.join(projectRoot, 'pnpm-lock.yaml'))) env.packageManager = 'pnpm';
    else if (fs.existsSync(path.join(projectRoot, 'yarn.lock'))) env.packageManager = 'yarn';

  } catch(e) { /* return defaults */ }

  return env;
}

// ═══════════════════════════════════════════════════════════════
// GRACEFUL FALLBACK
// ═══════════════════════════════════════════════════════════════

/**
 * Wrapper that ensures Sudarshana NEVER crashes the host application.
 * If any sandbox operation fails → log warning → pass through to original behavior.
 */
class GracefulFallback {
  constructor(options = {}) {
    this.mode = options.mode || 'protect'; // 'protect' | 'warn' | 'strict'
    this.logFile = options.logFile || null;
    this.fallbackCount = 0;
    this.errors = [];
  }

  /**
   * Wrap a function with graceful fallback
   * If the function throws → execute fallback instead
   */
  wrap(fn, fallback, context = '') {
    const self = this;
    return function(...args) {
      try {
        return fn.apply(this, args);
      } catch(e) {
        self.fallbackCount++;
        self.errors.push({
          context,
          error: e.message,
          timestamp: Date.now(),
          args: args.map(a => typeof a === 'string' ? a.substring(0, 100) : typeof a)
        });

        self._log(`[FALLBACK] ${context}: ${e.message}`);

        if (self.mode === 'strict') throw e; // Re-throw in strict mode
        if (typeof fallback === 'function') return fallback.apply(this, args);
        return fallback; // Return default value
      }
    };
  }

  /**
   * Wrap an async function with graceful fallback
   */
  wrapAsync(fn, fallback, context = '') {
    const self = this;
    return async function(...args) {
      try {
        return await fn.apply(this, args);
      } catch(e) {
        self.fallbackCount++;
        self.errors.push({ context, error: e.message, timestamp: Date.now() });
        self._log(`[FALLBACK] ${context}: ${e.message}`);

        if (self.mode === 'strict') throw e;
        if (typeof fallback === 'function') return fallback.apply(this, args);
        return fallback;
      }
    };
  }

  _log(message) {
    if (this.logFile) {
      try {
        fs.appendFileSync(this.logFile, `[${new Date().toISOString()}] ${message}\n`);
      } catch(e) {}
    }
  }

  getStats() {
    return {
      fallbackCount: this.fallbackCount,
      recentErrors: this.errors.slice(-10),
      mode: this.mode
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// TYPESCRIPT COMPATIBILITY
// ═══════════════════════════════════════════════════════════════

/**
 * Should Sudarshana sandbox this file?
 * Returns false for files that need to pass through to TS compilers
 */
function shouldSandbox(filePath, environment) {
  if (!filePath) return false;

  const ext = path.extname(filePath).toLowerCase();
  const normalized = normalizePath(filePath);

  // Never sandbox TypeScript source files (let ts-node/tsx handle them)
  if (['.ts', '.tsx', '.mts', '.cts'].includes(ext)) return false;

  // Never sandbox declaration files
  if (filePath.endsWith('.d.ts')) return false;

  // Never sandbox Sudarshana's own files
  if (normalized.includes('sudarshana')) return false;

  // Never sandbox bundler internals
  const bundlerPaths = ['webpack/', 'vite/', 'esbuild/', 'rollup/', 'parcel/'];
  if (bundlerPaths.some(bp => normalized.includes('/node_modules/' + bp))) {
    // Don't sandbox the bundler itself — it needs full access to compile
    return false;
  }

  // Never sandbox package managers
  const pmPaths = ['npm/', 'yarn/', 'pnpm/'];
  if (pmPaths.some(pm => normalized.includes('/node_modules/' + pm))) return false;

  // Never sandbox TypeScript compiler/runners
  const tsTools = ['ts-node/', 'tsx/', 'typescript/', '@swc/', 'esbuild-register/'];
  if (tsTools.some(t => normalized.includes('/node_modules/' + t))) return false;

  // Sandbox everything else in node_modules
  if (normalized.includes('/node_modules/')) return true;

  // Don't sandbox application code (trust level = system)
  return false;
}

// ═══════════════════════════════════════════════════════════════
// BUNDLER COMPATIBILITY
// ═══════════════════════════════════════════════════════════════

/**
 * Detect if we're running inside a bundler's build process
 * If yes → disable per-package hooks (code is already compiled into one bundle)
 */
function isRunningUnderBundler() {
  // Check common bundler environment variables
  if (process.env.WEBPACK_BUILD) return 'webpack';
  if (process.env.VITE_DEV_SERVER) return 'vite';
  if (process.env.ROLLUP_BUILD) return 'rollup';

  // Check if the entry point is a bundler
  const mainModule = process.argv[1] || '';
  if (mainModule.includes('webpack')) return 'webpack';
  if (mainModule.includes('vite')) return 'vite';
  if (mainModule.includes('esbuild')) return 'esbuild';
  if (mainModule.includes('rollup')) return 'rollup';

  // Check call stack for bundler presence
  try {
    const stack = new Error().stack || '';
    if (stack.includes('webpack')) return 'webpack';
    if (stack.includes('vite')) return 'vite';
  } catch(e) {}

  return false;
}

/**
 * Get the appropriate sandboxing strategy based on environment
 */
function getSandboxStrategy(environment) {
  // Under a bundler build → no per-package sandbox (code is compiled together)
  if (environment.bundler && isRunningUnderBundler()) {
    return {
      strategy: 'MONITOR_ONLY',
      reason: `Running under ${environment.bundler} — per-package isolation not applicable to bundled code`,
      hooks: ['env', 'honeypot'], // Only env + honeypot hooks work post-bundle
      skipModuleHooks: true
    };
  }

  // Serverless with cold-start sensitivity → lightweight mode
  if (environment.serverless) {
    return {
      strategy: 'LIGHTWEIGHT',
      reason: `Serverless (${environment.serverless}) — minimal overhead mode`,
      hooks: ['env', 'honeypot', 'network'], // Skip fs hooks (Lambda has restricted fs anyway)
      skipModuleHooks: false,
      cacheAggressively: true
    };
  }

  // Monorepo → need to handle workspace packages differently
  if (environment.monorepo) {
    return {
      strategy: 'WORKSPACE_AWARE',
      reason: `Monorepo (${environment.monorepo}) — workspace packages treated as application code`,
      hooks: ['all'],
      skipModuleHooks: false,
      treatWorkspacesAsApp: true
    };
  }

  // Standard project → full protection
  return {
    strategy: 'FULL',
    reason: 'Standard project — full per-package isolation',
    hooks: ['all'],
    skipModuleHooks: false
  };
}

// ═══════════════════════════════════════════════════════════════
// MONOREPO SUPPORT
// ═══════════════════════════════════════════════════════════════

/**
 * Find all workspace packages in a monorepo
 * These should be treated as "application code" (trust_level: system)
 */
function findWorkspacePackages(projectRoot) {
  const workspaces = [];

  // Check package.json workspaces field
  const pkgJsonPath = path.join(projectRoot, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      const wsConfig = pkg.workspaces;
      if (Array.isArray(wsConfig)) {
        for (const pattern of wsConfig) {
          const wsPath = path.join(projectRoot, pattern.replace('/*', ''));
          if (fs.existsSync(wsPath)) {
            try {
              const entries = fs.readdirSync(wsPath);
              for (const entry of entries) {
                const entryPkg = path.join(wsPath, entry, 'package.json');
                if (fs.existsSync(entryPkg)) {
                  const wsPkg = JSON.parse(fs.readFileSync(entryPkg, 'utf8'));
                  workspaces.push({ name: wsPkg.name, path: path.join(wsPath, entry) });
                }
              }
            } catch(e) {}
          }
        }
      }
    } catch(e) {}
  }

  // Check pnpm-workspace.yaml
  const pnpmWs = path.join(projectRoot, 'pnpm-workspace.yaml');
  if (fs.existsSync(pnpmWs)) {
    try {
      const content = fs.readFileSync(pnpmWs, 'utf8');
      const packageDirs = content.match(/- ['"]?([^'"\n]+)['"]?/g) || [];
      for (const match of packageDirs) {
        const dir = match.replace(/- ['"]?/, '').replace(/['"]$/, '').replace('/*', '');
        const fullDir = path.join(projectRoot, dir);
        if (fs.existsSync(fullDir)) {
          try {
            for (const entry of fs.readdirSync(fullDir)) {
              const entryPkg = path.join(fullDir, entry, 'package.json');
              if (fs.existsSync(entryPkg)) {
                const wsPkg = JSON.parse(fs.readFileSync(entryPkg, 'utf8'));
                workspaces.push({ name: wsPkg.name, path: path.join(fullDir, entry) });
              }
            }
          } catch(e) {}
        }
      }
    } catch(e) {}
  }

  return workspaces;
}

/**
 * Check if a file belongs to a workspace package (not node_modules)
 */
function isWorkspacePackage(filePath, workspaces) {
  const normalized = normalizePath(filePath);
  return workspaces.some(ws => normalized.startsWith(normalizePath(ws.path)));
}

// ═══════════════════════════════════════════════════════════════
// EJECT SUPPORT
// ═══════════════════════════════════════════════════════════════

/**
 * Instantly disable Sudarshana without uninstalling
 * Creates a .sudarshana-disabled file that the runtime checks on boot
 */
function eject(projectRoot) {
  const disableFile = path.join(projectRoot || process.cwd(), '.sudarshana-disabled');
  fs.writeFileSync(disableFile, JSON.stringify({
    disabled: true,
    timestamp: new Date().toISOString(),
    reason: 'Manual eject via `sudarshana eject`',
    reEnable: 'Delete this file or run `sudarshana enable`'
  }, null, 2));
  return disableFile;
}

/**
 * Re-enable Sudarshana after eject
 */
function enable(projectRoot) {
  const disableFile = path.join(projectRoot || process.cwd(), '.sudarshana-disabled');
  if (fs.existsSync(disableFile)) {
    fs.unlinkSync(disableFile);
    return true;
  }
  return false;
}

/**
 * Check if Sudarshana is disabled (ejected)
 */
function isDisabled(projectRoot) {
  const disableFile = path.join(projectRoot || process.cwd(), '.sudarshana-disabled');
  return fs.existsSync(disableFile);
}

// ═══════════════════════════════════════════════════════════════
// CIRCULAR DEPENDENCY PROTECTION
// ═══════════════════════════════════════════════════════════════

/**
 * Track require() depth to detect infinite loops
 * If depth > MAX_DEPTH → break the cycle, return partial module
 */
class CircularGuard {
  constructor(maxDepth = 100) {
    this.maxDepth = maxDepth;
    this.currentDepth = 0;
    this.loadingStack = new Set();
  }

  enter(modulePath) {
    this.currentDepth++;
    if (this.currentDepth > this.maxDepth) {
      throw new Error(`Sudarshana: Circular dependency depth exceeded (${this.maxDepth}). Breaking cycle at: ${modulePath}`);
    }
    if (this.loadingStack.has(modulePath)) {
      // Circular detected — return empty (same as Node.js behavior)
      return { circular: true };
    }
    this.loadingStack.add(modulePath);
    return { circular: false };
  }

  exit(modulePath) {
    this.currentDepth--;
    this.loadingStack.delete(modulePath);
  }
}

// ═══════════════════════════════════════════════════════════════
// DEBUG MODE
// ═══════════════════════════════════════════════════════════════

/**
 * Debug logger for "why was my package blocked?"
 * Enable with: SUDARSHANA_DEBUG=1 or --debug flag
 */
class DebugLogger {
  constructor(enabled = false) {
    this.enabled = enabled || process.env.SUDARSHANA_DEBUG === '1';
    this.events = [];
    this.maxEvents = 1000;
  }

  log(category, message, data = {}) {
    if (!this.enabled) return;

    const event = {
      time: new Date().toISOString(),
      category, // 'ALLOW' | 'BLOCK' | 'FALLBACK' | 'POLICY' | 'ERROR'
      message,
      ...data
    };

    this.events.push(event);
    if (this.events.length > this.maxEvents) this.events.shift();

    // Also output to stderr if debug mode is on
    const icon = { ALLOW: '✅', BLOCK: '🚫', FALLBACK: '⚠️', POLICY: '📋', ERROR: '❌' }[category] || '•';
    process.stderr.write(`[sudarshana:debug] ${icon} ${message}\n`);
  }

  /**
   * Explain why a specific package was blocked/allowed
   */
  explain(packageName) {
    return this.events.filter(e =>
      e.package === packageName || (e.message && e.message.includes(packageName))
    );
  }

  /**
   * Get all block events (for diagnosing "why doesn't my app work?")
   */
  getBlocks() {
    return this.events.filter(e => e.category === 'BLOCK');
  }

  /**
   * Dump debug log to file
   */
  dump(outputPath) {
    fs.writeFileSync(outputPath || '.sudarshana-debug.json', JSON.stringify({
      generated: new Date().toISOString(),
      eventCount: this.events.length,
      blocks: this.getBlocks().length,
      fallbacks: this.events.filter(e => e.category === 'FALLBACK').length,
      events: this.events
    }, null, 2));
  }
}

// ═══════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════

module.exports = {
  // Platform
  PLATFORM,

  // Path handling
  normalizePath,
  toOsPath,
  pathMatchesPolicy,

  // Environment detection
  detectEnvironment,
  isRunningUnderBundler,
  getSandboxStrategy,

  // TypeScript
  shouldSandbox,

  // Monorepo
  findWorkspacePackages,
  isWorkspacePackage,

  // Graceful fallback
  GracefulFallback,

  // Eject/Enable
  eject,
  enable,
  isDisabled,

  // Circular deps
  CircularGuard,

  // Debug
  DebugLogger,
};
