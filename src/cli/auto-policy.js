'use strict';

/**
 * SUDARSHANA — AUTO-POLICY GENERATOR (Anti-Shakuni)
 * 
 * "The best security is security you don't have to think about."
 * 
 * This module scans your project and automatically generates
 * per-package security policies by:
 * 
 * 1. Reading package.json (yours + each dependency)
 * 2. Analyzing dependency trees (what does each pkg actually need?)
 * 3. Cross-referencing with known-safe presets (lodash = pure compute)
 * 4. Detecting red flags (postinstall, native addons, network deps)
 * 5. Generating a .sudarshana.json ready to use — ZERO manual config
 * 
 * Usage:
 *   sudarshana init          → generates config for your project
 *   sudarshana init --strict → maximum restriction (deny all + learn)
 *   sudarshana init --report → show what each package needs, don't write
 */

const fs = require('fs');
const path = require('path');
const { KNOWN_PACKAGE_POLICIES, DEFAULT_POLICY, SENSITIVE_PATHS } = require('../kernel/policy-engine');

// Packages whose primary purpose involves network
const NETWORK_PACKAGES = new Set([
  'axios', 'node-fetch', 'got', 'request', 'superagent', 'undici',
  'http-proxy', 'express', 'fastify', 'koa', 'hapi', 'restify',
  'socket.io', 'ws', 'mqtt', 'amqplib', 'redis', 'ioredis',
  'mongoose', 'pg', 'mysql', 'mysql2', 'mssql', 'sequelize',
  'typeorm', 'prisma', 'knex', 'nodemailer', 'twilio', 'stripe',
  'aws-sdk', '@aws-sdk/client-s3', 'firebase', 'graphql-request'
]);

// Packages that are pure compute (ZERO capabilities needed)
const PURE_COMPUTE_PACKAGES = new Set([
  'lodash', 'underscore', 'ramda', 'fp-ts', 'immutable',
  'uuid', 'nanoid', 'cuid', 'shortid',
  'moment', 'dayjs', 'date-fns', 'luxon',
  'validator', 'joi', 'yup', 'zod', 'ajv', 'superstruct',
  'chalk', 'colors', 'kleur', 'picocolors',
  'debug', 'ms', 'bytes', 'pretty-bytes',
  'semver', 'compare-versions',
  'deepmerge', 'deep-equal', 'fast-deep-equal',
  'camelcase', 'snake-case', 'change-case',
  'pluralize', 'slugify', 'escape-html',
  'mime', 'mime-types', 'content-type',
  'qs', 'query-string', 'url-parse',
  'path-to-regexp', 'minimatch', 'micromatch', 'picomatch',
  'eventemitter3', 'mitt', 'tiny-emitter',
  'tslib', 'core-js', 'regenerator-runtime',
  'buffer', 'safe-buffer', 'base64-js',
  'ieee754', 'bn.js', 'bignumber.js',
  'clsx', 'classnames', 'tailwind-merge'
]);

// Packages that need filesystem access
const FS_PACKAGES = new Set([
  'fs-extra', 'graceful-fs', 'glob', 'globby', 'fast-glob',
  'chokidar', 'watchman', 'rimraf', 'del', 'make-dir', 'mkdirp',
  'tmp', 'temp', 'find-up', 'locate-path', 'pkg-up',
  'read-pkg', 'write-pkg', 'load-json-file', 'write-json-file',
  'yaml', 'js-yaml', 'toml', 'ini', 'dotenv', 'cosmiconfig',
  'rc', 'conf', 'configstore', 'env-paths'
]);

// Packages that execute shell commands (HIGH RISK)
const SHELL_PACKAGES = new Set([
  'execa', 'cross-spawn', 'shelljs', 'child-process-promise',
  'npm-run-all', 'concurrently', 'run-script-os',
  'husky', 'lint-staged', 'simple-git'
]);

// Packages with native addons (ELEVATED RISK)
const NATIVE_PACKAGES = new Set([
  'sharp', 'canvas', 'better-sqlite3', 'sqlite3', 'bcrypt',
  'node-sass', 'libsass', 'fsevents', 'node-gyp',
  'cpu-features', 'microtime', 'usb', 'serialport',
  'leveldown', 'rocksdb', 'lmdb', 'sodium-native',
  'argon2', 're2', 'farmhash', 'xxhash'
]);

class AutoPolicyGenerator {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.packageJsonPath = path.join(this.projectRoot, 'package.json');
    this.nodeModulesPath = path.join(this.projectRoot, 'node_modules');
    this.warnings = [];
    this.suggestions = [];
  }

  /**
   * Generate complete policy configuration for a project
   * @param {Object} options - { strict: boolean, report: boolean }
   * @returns {Object} Generated .sudarshana.json content
   */
  generate(options = {}) {
    const { strict = false } = options;

    // 1. Read project's package.json
    if (!fs.existsSync(this.packageJsonPath)) {
      throw new Error(`No package.json found in ${this.projectRoot}`);
    }
    const projectPkg = JSON.parse(fs.readFileSync(this.packageJsonPath, 'utf8'));

    // 2. Get all direct dependencies
    const allDeps = {
      ...projectPkg.dependencies,
      ...projectPkg.devDependencies
    };

    // 3. Analyze each dependency and generate policy
    const policies = {
      '_application_': {
        trust_level: 'system',
        env_visible: ['*'],
        fs_read: ['*'],
        fs_write: ['*'],
        network: ['*'],
        shell: ['*'],
        allow_native_addons: true,
        allow_wasm: true,
        _comment: 'Your own application code — full access'
      }
    };

    const depNames = Object.keys(allDeps);
    const stats = { pure: 0, network: 0, fs: 0, shell: 0, native: 0, unknown: 0 };

    for (const depName of depNames) {
      const policy = this._analyzePackage(depName, strict);
      policies[depName] = policy;

      // Count stats
      if (policy._category === 'pure_compute') stats.pure++;
      else if (policy._category === 'network') stats.network++;
      else if (policy._category === 'filesystem') stats.fs++;
      else if (policy._category === 'shell') stats.shell++;
      else if (policy._category === 'native') stats.native++;
      else stats.unknown++;
    }

    // 4. Generate full config
    const config = {
      $schema: 'https://sudarshana.dev/config-schema.json',
      $generated: new Date().toISOString(),
      $generator: 'sudarshana init',

      mode: strict ? 'lockdown' : 'enforce',
      projectRoot: '.',
      enableHoneypots: true,
      onViolation: strict ? 'kill' : 'log',
      reportPath: './.sudarshana-report.json',

      policies,

      _stats: {
        totalDependencies: depNames.length,
        ...stats,
        warnings: this.warnings.length
      }
    };

    // 5. Clean up internal markers
    for (const [name, policy] of Object.entries(config.policies)) {
      delete policy._category;
    }

    return config;
  }

  /**
   * Analyze a single package and suggest its policy
   */
  _analyzePackage(packageName, strict) {
    // 1. Check known presets first
    if (KNOWN_PACKAGE_POLICIES[packageName]) {
      return { ...KNOWN_PACKAGE_POLICIES[packageName], _category: 'known_preset' };
    }

    // 2. Check category sets
    if (PURE_COMPUTE_PACKAGES.has(packageName)) {
      return {
        trust_level: 'trusted',
        env_visible: [],
        fs_read: [],
        fs_write: [],
        network: [],
        shell: [],
        _category: 'pure_compute',
        _comment: `Pure utility — zero capabilities needed`
      };
    }

    if (NETWORK_PACKAGES.has(packageName)) {
      return {
        trust_level: 'limited',
        env_visible: ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'],
        fs_read: [],
        fs_write: [],
        network: ['CONFIGURE_YOUR_DOMAINS_HERE'],
        shell: [],
        _category: 'network',
        _comment: `⚠️ Needs network — declare allowed domains!`,
        _action_required: true
      };
    }

    if (FS_PACKAGES.has(packageName)) {
      return {
        trust_level: 'limited',
        env_visible: ['NODE_ENV'],
        fs_read: ['./*'],
        fs_write: strict ? [] : ['./*'],
        network: [],
        shell: [],
        _category: 'filesystem',
        _comment: `File system access — scoped to project root`
      };
    }

    if (SHELL_PACKAGES.has(packageName)) {
      this.warnings.push({
        package: packageName,
        risk: 'HIGH',
        reason: 'Executes shell commands — review if actually needed'
      });
      return {
        trust_level: 'limited',
        env_visible: ['PATH', 'PATHEXT', 'NODE_ENV'],
        fs_read: ['./*'],
        fs_write: [],
        network: [],
        shell: strict ? [] : ['node', 'npm', 'npx'],
        _category: 'shell',
        _comment: `⚠️ HIGH RISK: Shell execution. Review if needed.`
      };
    }

    if (NATIVE_PACKAGES.has(packageName)) {
      this.warnings.push({
        package: packageName,
        risk: 'ELEVATED',
        reason: 'Native addon — can bypass JS-level monitoring'
      });
      return {
        trust_level: 'limited',
        env_visible: [],
        fs_read: [`./node_modules/${packageName}/*`],
        fs_write: [],
        network: [],
        shell: [],
        allow_native_addons: true,
        _category: 'native',
        _comment: `⚠️ Native addon — operates below JS monitoring layer`
      };
    }

    // 3. Unknown package — try to infer from its package.json
    return this._inferFromPackageJson(packageName, strict);
  }

  /**
   * Infer policy from a package's own package.json
   */
  _inferFromPackageJson(packageName, strict) {
    const pkgJsonPath = path.join(this.nodeModulesPath, packageName, 'package.json');

    if (!fs.existsSync(pkgJsonPath)) {
      // Can't analyze — use strictest defaults
      this.warnings.push({
        package: packageName,
        risk: 'UNKNOWN',
        reason: 'Not installed — cannot analyze. Using deny-all.'
      });
      return {
        trust_level: 'untrusted',
        env_visible: [],
        fs_read: [],
        fs_write: [],
        network: [],
        shell: [],
        _category: 'unknown',
        _comment: `Unknown package — using deny-all (install & re-run to analyze)`
      };
    }

    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      const policy = { trust_level: 'limited', _category: 'inferred' };
      const needs = [];

      // Check if it has network-related dependencies
      const deps = Object.keys(pkg.dependencies || {});
      const hasNetDeps = deps.some(d => NETWORK_PACKAGES.has(d));
      const hasFsDeps = deps.some(d => FS_PACKAGES.has(d));
      const hasShellDeps = deps.some(d => SHELL_PACKAGES.has(d));

      // Assign capabilities based on what it depends on
      policy.env_visible = ['NODE_ENV'];
      policy.fs_read = hasFsDeps ? ['./*'] : [];
      policy.fs_write = [];
      policy.network = hasNetDeps ? ['CONFIGURE_YOUR_DOMAINS_HERE'] : [];
      policy.shell = hasShellDeps && !strict ? ['node'] : [];

      if (hasNetDeps) needs.push('network');
      if (hasFsDeps) needs.push('filesystem');
      if (hasShellDeps) needs.push('shell');

      // Check for red flags
      if (pkg.scripts && (pkg.scripts.postinstall || pkg.scripts.preinstall)) {
        this.warnings.push({
          package: packageName,
          risk: 'HIGH',
          reason: `Has ${pkg.scripts.postinstall ? 'postinstall' : 'preinstall'} script`
        });
      }

      if (pkg.gypfile || (pkg.scripts && pkg.scripts.install && pkg.scripts.install.includes('node-gyp'))) {
        policy.allow_native_addons = true;
        this.warnings.push({
          package: packageName,
          risk: 'ELEVATED',
          reason: 'Uses node-gyp (native compilation)'
        });
      }

      // No repo = suspicious
      if (!pkg.repository) {
        this.warnings.push({
          package: packageName,
          risk: 'LOW',
          reason: 'No repository URL in package.json'
        });
      }

      policy._comment = needs.length > 0
        ? `Inferred: needs ${needs.join(', ')}. Review and restrict further.`
        : `Inferred: appears to be pure compute. Verify.`;

      if (policy.network.includes('CONFIGURE_YOUR_DOMAINS_HERE')) {
        policy._action_required = true;
      }

      return policy;
    } catch (e) {
      return {
        trust_level: 'untrusted',
        env_visible: [],
        fs_read: [],
        fs_write: [],
        network: [],
        shell: [],
        _category: 'unknown',
        _comment: `Could not analyze: ${e.message}. Using deny-all.`
      };
    }
  }

  /**
   * Generate a human-readable report of what was analyzed
   */
  generateReport(config) {
    const lines = [];
    lines.push('');
    lines.push('╔══════════════════════════════════════════════════════════════════╗');
    lines.push('║  🔥 SUDARSHANA — Auto-Generated Policy Report                   ║');
    lines.push('╠══════════════════════════════════════════════════════════════════╣');
    lines.push(`║  Project: ${path.basename(this.projectRoot).padEnd(51)}║`);
    lines.push(`║  Dependencies: ${String(config._stats.totalDependencies).padEnd(47)}║`);
    lines.push(`║  Generated: ${new Date().toISOString().padEnd(49)}║`);
    lines.push('╚══════════════════════════════════════════════════════════════════╝');
    lines.push('');
    lines.push('📊 DEPENDENCY CLASSIFICATION:');
    lines.push(`  🟢 Pure compute (zero access):     ${config._stats.pure}`);
    lines.push(`  🔵 Filesystem access:              ${config._stats.fs}`);
    lines.push(`  🟡 Network access:                 ${config._stats.network}`);
    lines.push(`  🟠 Shell execution:                ${config._stats.shell}`);
    lines.push(`  🔴 Native addons:                  ${config._stats.native}`);
    lines.push(`  ⚪ Unknown (deny-all):             ${config._stats.unknown}`);
    lines.push('');

    if (this.warnings.length > 0) {
      lines.push('⚠️  WARNINGS:');
      for (const w of this.warnings) {
        const icon = w.risk === 'HIGH' ? '🔴' : w.risk === 'ELEVATED' ? '🟠' : '🟡';
        lines.push(`  ${icon} ${w.package}: ${w.reason}`);
      }
      lines.push('');
    }

    // Action required items
    const actionRequired = Object.entries(config.policies)
      .filter(([_, p]) => p._action_required);

    if (actionRequired.length > 0) {
      lines.push('📝 ACTION REQUIRED (configure allowed domains):');
      for (const [name] of actionRequired) {
        lines.push(`  → ${name}: Set allowed network domains in policy`);
      }
      lines.push('');
    }

    lines.push('✅ READY TO USE:');
    lines.push('  1. Review .sudarshana.json (auto-generated)');
    lines.push('  2. Replace "CONFIGURE_YOUR_DOMAINS_HERE" with actual domains');
    lines.push('  3. Run: node --require sudarshana/src/index-v2 your-app.js');
    lines.push('');
    lines.push('  That\'s it. Shakuni defeated. 🎲→🔥');
    lines.push('');

    return lines.join('\n');
  }
}

/**
 * CLI entry point for `sudarshana init`
 */
function runInit(options = {}) {
  const generator = new AutoPolicyGenerator(process.cwd());

  console.log('\n🔥 Sudarshana — Generating security policies...\n');

  const config = generator.generate(options);

  // Print report
  const report = generator.generateReport(config);
  console.log(report);

  // Write config file (unless --report only)
  if (!options.report) {
    const configPath = path.join(process.cwd(), '.sudarshana.json');

    // Clean internal markers before writing
    const cleanConfig = JSON.parse(JSON.stringify(config));
    delete cleanConfig._stats;
    for (const policy of Object.values(cleanConfig.policies)) {
      delete policy._action_required;
    }

    fs.writeFileSync(configPath, JSON.stringify(cleanConfig, null, 2));
    console.log(`✅ Config written to: ${configPath}`);
    console.log('   Edit network domains, then run your app with Sudarshana.\n');
  }

  return config;
}

module.exports = { AutoPolicyGenerator, runInit };
