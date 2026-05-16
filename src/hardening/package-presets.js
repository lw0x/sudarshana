'use strict';

/**
 * SUDARSHANA — PACKAGE-SPECIFIC PRESETS
 * 
 * "We know what popular packages need. You don't have to configure them."
 * 
 * These presets handle packages that would break under default deny-all:
 * - Build tools (esbuild, swc, webpack)
 * - ORMs (Prisma, TypeORM, Sequelize)
 * - Test frameworks (Jest, Mocha, Vitest)
 * - Frameworks (Next.js, Nest.js, Nuxt)
 * - Image processing (Sharp, Jimp)
 * - Native addons (bcrypt, better-sqlite3)
 * 
 * ALSO handles known conflicts:
 * - Jest vs Sudarshana (both hook Module._load)
 * - Next.js custom resolution
 * - Prisma native binary
 * 
 * Usage: Auto-applied by `sudarshana init` when these packages are detected.
 *        Or manually: sudarshana init --presets
 */

// ═══════════════════════════════════════════════════════════════
// PRESET CATEGORIES
// ═══════════════════════════════════════════════════════════════

/**
 * PURE COMPUTE — zero capabilities needed
 * These packages do math/strings/data transformation only.
 */
const PURE_COMPUTE = {
  // Utility libraries
  'lodash': {}, 'underscore': {}, 'ramda': {}, 'fp-ts': {}, 'immutable': {},
  'lodash-es': {}, 'lodash.get': {}, 'lodash.merge': {}, 'lodash.clonedeep': {},
  
  // ID generators
  'uuid': {}, 'nanoid': {}, 'cuid': {}, 'ulid': {}, 'shortid': {},
  
  // Date/time
  'moment': {}, 'dayjs': {}, 'date-fns': {}, 'luxon': {},
  
  // Validation
  'joi': {}, 'yup': {}, 'zod': {}, 'ajv': {}, 'validator': {}, 'superstruct': {},
  'class-validator': {}, 'class-transformer': {},
  
  // String manipulation
  'chalk': {}, 'colors': {}, 'kleur': {}, 'picocolors': {},
  'slugify': {}, 'escape-html': {}, 'he': {}, 'entities': {},
  'camelcase': {}, 'snake-case': {}, 'change-case': {}, 'pluralize': {},
  
  // Math/numbers
  'bignumber.js': {}, 'decimal.js': {}, 'bn.js': {}, 'mathjs': {},
  
  // Data structures
  'deepmerge': {}, 'deep-equal': {}, 'fast-deep-equal': {}, 'rfdc': {},
  'immer': {}, 'structuredClone': {},
  
  // Parsing (no I/O)
  'qs': {}, 'query-string': {}, 'url-parse': {}, 'content-type': {},
  'mime': {}, 'mime-types': {}, 'semver': {}, 'ms': {}, 'bytes': {},
  'path-to-regexp': {}, 'minimatch': {}, 'micromatch': {}, 'picomatch': {},
  
  // React/frontend (when used in SSR)
  'react': {}, 'react-dom': {}, 'preact': {},
  'clsx': {}, 'classnames': {}, 'tailwind-merge': {},
  
  // Encoding (pure functions)
  'base64-js': {}, 'ieee754': {}, 'safe-buffer': {}, 'buffer': {},
  
  // Type utilities
  'tslib': {}, 'core-js': {}, 'regenerator-runtime': {},
  '@babel/runtime': {}, '@swc/helpers': {},
};

/**
 * NETWORK PACKAGES — need specific domain access
 * Policy: network allowed, env for proxy settings only
 */
const NETWORK_PACKAGES = {
  'axios': {
    env_visible: ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy'],
    network: ['CONFIGURE_YOUR_DOMAINS'],
    fs_read: [],
    shell: [],
  },
  'node-fetch': {
    env_visible: ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'],
    network: ['CONFIGURE_YOUR_DOMAINS'],
    fs_read: [],
    shell: [],
  },
  'got': {
    env_visible: ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'],
    network: ['CONFIGURE_YOUR_DOMAINS'],
    fs_read: [],
    shell: [],
  },
  'undici': {
    env_visible: ['HTTP_PROXY', 'HTTPS_PROXY'],
    network: ['CONFIGURE_YOUR_DOMAINS'],
    fs_read: [],
    shell: [],
  },
  'superagent': {
    env_visible: ['HTTP_PROXY', 'HTTPS_PROXY'],
    network: ['CONFIGURE_YOUR_DOMAINS'],
    fs_read: [],
    shell: [],
  },
};

/**
 * WEB FRAMEWORKS — need PORT, env, localhost binding, template reading
 */
const FRAMEWORKS = {
  'express': {
    env_visible: ['PORT', 'HOST', 'NODE_ENV'],
    network: ['0.0.0.0', 'localhost', '127.0.0.1'],
    fs_read: ['./views/*', './public/*', './static/*'],
    fs_write: [],
    shell: [],
  },
  'fastify': {
    env_visible: ['PORT', 'HOST', 'NODE_ENV', 'FASTIFY_ADDRESS'],
    network: ['0.0.0.0', 'localhost', '127.0.0.1'],
    fs_read: ['./schemas/*', './plugins/*'],
    fs_write: [],
    shell: [],
  },
  'koa': {
    env_visible: ['PORT', 'HOST', 'NODE_ENV'],
    network: ['0.0.0.0', 'localhost', '127.0.0.1'],
    fs_read: ['./views/*', './public/*'],
    fs_write: [],
    shell: [],
  },
  'hapi': {
    env_visible: ['PORT', 'HOST', 'NODE_ENV'],
    network: ['0.0.0.0', 'localhost', '127.0.0.1'],
    fs_read: [],
    shell: [],
  },
  '@nestjs/core': {
    env_visible: ['PORT', 'HOST', 'NODE_ENV'],
    network: ['0.0.0.0', 'localhost', '127.0.0.1'],
    fs_read: ['./dist/*', './src/*'],
    fs_write: [],
    shell: [],
    _note: 'NestJS needs broad fs access for its DI container scanning',
  },
  '@nestjs/common': { _inherit: '@nestjs/core' },
  '@nestjs/platform-express': { _inherit: 'express' },
};

/**
 * DATABASE/ORM — need DATABASE_URL and specific network hosts
 */
const DATABASE_PACKAGES = {
  'pg': {
    env_visible: ['DATABASE_URL', 'PGHOST', 'PGPORT', 'PGUSER', 'PGPASSWORD', 'PGDATABASE', 'PGSSLMODE'],
    network: ['CONFIGURE_DB_HOST'],
    fs_read: [],
    shell: [],
  },
  'mysql2': {
    env_visible: ['DATABASE_URL', 'MYSQL_HOST', 'MYSQL_PORT', 'MYSQL_USER', 'MYSQL_PASSWORD'],
    network: ['CONFIGURE_DB_HOST'],
    fs_read: [],
    shell: [],
  },
  'mongoose': {
    env_visible: ['MONGODB_URI', 'MONGO_URL', 'DATABASE_URL'],
    network: ['CONFIGURE_DB_HOST'],
    fs_read: [],
    shell: [],
  },
  'redis': {
    env_visible: ['REDIS_URL', 'REDIS_HOST', 'REDIS_PORT'],
    network: ['CONFIGURE_REDIS_HOST'],
    fs_read: [],
    shell: [],
  },
  'ioredis': { _inherit: 'redis' },
  '@prisma/client': {
    env_visible: ['DATABASE_URL', 'DIRECT_URL'],
    network: ['CONFIGURE_DB_HOST'],
    fs_read: ['./node_modules/.prisma/*', './node_modules/@prisma/*', './prisma/*'],
    fs_write: [],
    shell: [],
    allow_native_addons: true,
    _note: 'Prisma uses native query engine binary',
  },
  'sequelize': {
    env_visible: ['DATABASE_URL', 'DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASS', 'DB_NAME'],
    network: ['CONFIGURE_DB_HOST'],
    fs_read: ['./migrations/*', './models/*'],
    shell: [],
  },
  'typeorm': {
    env_visible: ['DATABASE_URL', 'TYPEORM_HOST', 'TYPEORM_PORT', 'TYPEORM_USERNAME', 'TYPEORM_PASSWORD'],
    network: ['CONFIGURE_DB_HOST'],
    fs_read: ['./src/entity/*', './src/migration/*'],
    shell: [],
  },
  'knex': {
    env_visible: ['DATABASE_URL'],
    network: ['CONFIGURE_DB_HOST'],
    fs_read: ['./migrations/*', './seeds/*'],
    shell: [],
  },
};

/**
 * BUILD TOOLS — need full access during BUILD but not runtime
 * Strategy: BYPASS during build, SANDBOX at runtime
 */
const BUILD_TOOLS = {
  'webpack': { _bypass: true, _reason: 'Build tool — needs full access to compile' },
  'webpack-cli': { _bypass: true, _reason: 'Build tool CLI' },
  'vite': { _bypass: true, _reason: 'Build tool + dev server' },
  'esbuild': { _bypass: true, _reason: 'Native Go binary — cannot be sandboxed in JS', allow_native_addons: true },
  'rollup': { _bypass: true, _reason: 'Build tool' },
  'parcel': { _bypass: true, _reason: 'Build tool' },
  '@swc/core': { _bypass: true, _reason: 'Native Rust binary', allow_native_addons: true },
  'typescript': { _bypass: true, _reason: 'Compiler — needs full fs access' },
  'ts-node': { _bypass: true, _reason: 'TS compiler wrapper' },
  'tsx': { _bypass: true, _reason: 'TS executor' },
  'babel-loader': { _bypass: true, _reason: 'Build plugin' },
  '@babel/core': { _bypass: true, _reason: 'Compiler' },
  'postcss': { _bypass: true, _reason: 'CSS build tool' },
  'tailwindcss': { _bypass: true, _reason: 'CSS build tool — scans all source files' },
  'sass': { _bypass: true, _reason: 'CSS compiler' },
  'less': { _bypass: true, _reason: 'CSS compiler' },
};

/**
 * TEST FRAMEWORKS — need broad access + conflict resolution
 * Strategy: BYPASS or COEXIST (disable module hooks, keep env/honeypot)
 */
const TEST_FRAMEWORKS = {
  'jest': {
    _bypass: true,
    _conflict: 'MODULE_LOAD_HOOK',
    _reason: 'Jest replaces Module._load itself (vm-based isolation). Two hooks conflict.',
    _coexist_strategy: 'Disable Sudarshana module hooks. Keep env/honeypot protection only.',
  },
  'jest-worker': { _bypass: true, _reason: 'Jest worker — needs full module access' },
  '@jest/core': { _bypass: true, _reason: 'Jest core' },
  'mocha': { _bypass: true, _reason: 'Test runner — needs to load all test files' },
  'vitest': { _bypass: true, _reason: 'Vite-based test runner' },
  'ava': { _bypass: true, _reason: 'Test runner with worker threads' },
  'tap': { _bypass: true, _reason: 'Test runner' },
  'nyc': { _bypass: true, _reason: 'Coverage tool — hooks require()' },
  'c8': { _bypass: true, _reason: 'Coverage tool' },
  'istanbul': { _bypass: true, _reason: 'Coverage tool' },
};

/**
 * NATIVE ADDON PACKAGES — need allow_native_addons + specific permissions
 */
const NATIVE_PACKAGES = {
  'sharp': {
    env_visible: [],
    network: [],
    fs_read: ['CONFIGURE_IMAGE_PATHS'],
    fs_write: ['CONFIGURE_OUTPUT_PATHS'],
    shell: [],
    allow_native_addons: true,
    _note: 'Native libvips — image processing only, no network needed at runtime',
  },
  'bcrypt': {
    env_visible: [],
    network: [],
    fs_read: [],
    fs_write: [],
    shell: [],
    allow_native_addons: true,
    _note: 'Pure compute (hashing) — zero I/O needed',
  },
  'argon2': { _inherit: 'bcrypt' },
  'better-sqlite3': {
    env_visible: [],
    network: [],
    fs_read: ['CONFIGURE_DB_PATH'],
    fs_write: ['CONFIGURE_DB_PATH'],
    shell: [],
    allow_native_addons: true,
    _note: 'File-based DB — needs specific file path only',
  },
  'canvas': {
    env_visible: [],
    network: [],
    fs_read: ['./fonts/*'],
    fs_write: [],
    shell: [],
    allow_native_addons: true,
  },
  'node-sass': { _bypass: true, allow_native_addons: true, _reason: 'Build-time only' },
};

/**
 * NEXT.JS ECOSYSTEM — needs special handling
 * Next.js uses custom module resolution, worker threads, and dynamic requires
 */
const NEXTJS_PACKAGES = {
  'next': {
    _bypass: true,
    _conflict: 'CUSTOM_RESOLUTION',
    _reason: 'Next.js has its own module resolution, compiler (SWC), and worker threads.',
    _coexist_strategy: 'Bypass Next.js internals. Sandbox user dependencies only.',
  },
  '@next/env': { _bypass: true },
  '@next/swc-darwin-arm64': { _bypass: true, allow_native_addons: true },
  '@next/swc-darwin-x64': { _bypass: true, allow_native_addons: true },
  '@next/swc-linux-x64-gnu': { _bypass: true, allow_native_addons: true },
  '@next/swc-win32-x64-msvc': { _bypass: true, allow_native_addons: true },
};

/**
 * CLOUD SDKs — need AWS/GCP/Azure credentials + their endpoints
 */
const CLOUD_SDKS = {
  'aws-sdk': {
    env_visible: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                  'AWS_REGION', 'AWS_DEFAULT_REGION', 'AWS_PROFILE'],
    network: ['*.amazonaws.com', '*.aws.amazon.com'],
    fs_read: ['~/.aws/*'],
    shell: [],
  },
  '@aws-sdk/client-s3': { _inherit: 'aws-sdk' },
  '@aws-sdk/client-dynamodb': { _inherit: 'aws-sdk' },
  '@aws-sdk/client-sqs': { _inherit: 'aws-sdk' },
  '@aws-sdk/client-sns': { _inherit: 'aws-sdk' },
  '@aws-sdk/client-lambda': { _inherit: 'aws-sdk' },
  '@google-cloud/storage': {
    env_visible: ['GOOGLE_APPLICATION_CREDENTIALS', 'GCLOUD_PROJECT', 'GCP_PROJECT'],
    network: ['*.googleapis.com', 'accounts.google.com'],
    fs_read: ['CONFIGURE_CREDENTIALS_PATH'],
    shell: [],
  },
  'firebase-admin': {
    env_visible: ['FIREBASE_CONFIG', 'GOOGLE_APPLICATION_CREDENTIALS'],
    network: ['*.firebaseio.com', '*.googleapis.com'],
    fs_read: [],
    shell: [],
  },
};

/**
 * LOGGING — need fs write for log files, possibly network for remote logging
 */
const LOGGING_PACKAGES = {
  'winston': {
    env_visible: ['LOG_LEVEL', 'NODE_ENV'],
    fs_read: [],
    fs_write: ['./logs/*', '/var/log/*'],
    network: [],
    shell: [],
  },
  'pino': {
    env_visible: ['LOG_LEVEL', 'NODE_ENV'],
    fs_read: [],
    fs_write: ['./logs/*'],
    network: [],
    shell: [],
  },
  'bunyan': { _inherit: 'winston' },
  'morgan': {
    env_visible: ['NODE_ENV'],
    fs_read: [],
    fs_write: ['./logs/*'],
    network: [],
    shell: [],
  },
};

/**
 * MESSAGING/QUEUES — need specific broker connections
 */
const MESSAGING_PACKAGES = {
  'amqplib': {
    env_visible: ['AMQP_URL', 'RABBITMQ_URL'],
    network: ['CONFIGURE_BROKER_HOST'],
    fs_read: [],
    shell: [],
  },
  'kafkajs': {
    env_visible: ['KAFKA_BROKERS', 'KAFKA_CLIENT_ID'],
    network: ['CONFIGURE_KAFKA_BROKERS'],
    fs_read: [],
    shell: [],
  },
  'bull': {
    env_visible: ['REDIS_URL'],
    network: ['CONFIGURE_REDIS_HOST'],
    fs_read: [],
    shell: [],
  },
  'bullmq': { _inherit: 'bull' },
};

// ═══════════════════════════════════════════════════════════════
// CONFLICT RESOLUTION
// ═══════════════════════════════════════════════════════════════

/**
 * Known conflicts between Sudarshana and specific packages
 * When detected: apply coexistence strategy instead of breaking
 */
const KNOWN_CONFLICTS = {
  'jest': {
    type: 'MODULE_LOAD_HOOK',
    description: 'Jest and Sudarshana both hook Module._load',
    strategy: 'HONEYPOT_ONLY',
    // In this mode: disable module isolation, keep ONLY honeypot + env protection
    disableHooks: ['fs', 'net', 'http', 'dns', 'shell'],
    keepHooks: ['env', 'honeypot', 'behavioral'],
  },
  'next': {
    type: 'CUSTOM_RESOLUTION',
    description: 'Next.js uses custom module resolution that conflicts with our interception',
    strategy: 'BYPASS_FRAMEWORK',
    // Bypass all @next/* packages, sandbox only user code + third-party
    bypassPatterns: ['next/', '@next/', '__next/'],
  },
  'nyc': {
    type: 'REQUIRE_HOOK',
    description: 'NYC instruments require() for coverage — conflicts with our hook',
    strategy: 'LOAD_ORDER',
    // Sudarshana must load AFTER NYC (or coexist via hook chaining)
    loadOrder: 'after',
  },
  'ts-node': {
    type: 'EXTENSION_HANDLER',
    description: 'ts-node registers .ts extension handler',
    strategy: 'PASSTHROUGH',
    // Don't intercept .ts files — let ts-node compile first, then sandbox the output
    passthroughExtensions: ['.ts', '.tsx', '.mts', '.cts'],
  },
};

// ═══════════════════════════════════════════════════════════════
// PRESET RESOLVER
// ═══════════════════════════════════════════════════════════════

class PresetResolver {
  constructor() {
    // Build the complete preset map
    this.presets = new Map();
    this._registerCategory(PURE_COMPUTE, 'pure_compute');
    this._registerCategory(NETWORK_PACKAGES, 'network');
    this._registerCategory(FRAMEWORKS, 'framework');
    this._registerCategory(DATABASE_PACKAGES, 'database');
    this._registerCategory(BUILD_TOOLS, 'build_tool');
    this._registerCategory(TEST_FRAMEWORKS, 'test_framework');
    this._registerCategory(NATIVE_PACKAGES, 'native');
    this._registerCategory(NEXTJS_PACKAGES, 'nextjs');
    this._registerCategory(CLOUD_SDKS, 'cloud');
    this._registerCategory(LOGGING_PACKAGES, 'logging');
    this._registerCategory(MESSAGING_PACKAGES, 'messaging');
  }

  _registerCategory(packages, category) {
    for (const [name, config] of Object.entries(packages)) {
      this.presets.set(name, { ...config, _category: category });
    }
  }

  /**
   * Get preset for a package (returns null if unknown)
   */
  getPreset(packageName) {
    const preset = this.presets.get(packageName);
    if (!preset) return null;

    // Handle inheritance
    if (preset._inherit) {
      const parent = this.presets.get(preset._inherit);
      if (parent) return { ...parent, ...preset, _inherit: undefined };
    }

    return preset;
  }

  /**
   * Generate full policy from preset
   */
  generatePolicy(packageName) {
    const preset = this.getPreset(packageName);

    if (!preset) {
      // Unknown package → deny-all
      return {
        trust_level: 'untrusted',
        env_visible: [],
        fs_read: [],
        fs_write: [],
        network: [],
        shell: [],
      };
    }

    // Pure compute → zero access
    if (preset._category === 'pure_compute') {
      return {
        trust_level: 'trusted',
        env_visible: [],
        fs_read: [],
        fs_write: [],
        network: [],
        shell: [],
        _preset: 'pure_compute',
      };
    }

    // Bypass packages → system trust
    if (preset._bypass) {
      return {
        trust_level: 'system',
        env_visible: ['*'],
        fs_read: ['*'],
        fs_write: ['*'],
        network: ['*'],
        shell: ['*'],
        _bypass: true,
        _reason: preset._reason,
      };
    }

    // Standard preset → specific permissions
    return {
      trust_level: 'limited',
      env_visible: preset.env_visible || [],
      fs_read: preset.fs_read || [],
      fs_write: preset.fs_write || [],
      network: preset.network || [],
      shell: preset.shell || [],
      allow_native_addons: preset.allow_native_addons || false,
      _preset: preset._category,
    };
  }

  /**
   * Check if a package has a known conflict with Sudarshana
   */
  getConflict(packageName) {
    return KNOWN_CONFLICTS[packageName] || null;
  }

  /**
   * Detect all conflicts in a project's dependencies
   */
  detectConflicts(dependencies) {
    const conflicts = [];
    for (const dep of dependencies) {
      const conflict = this.getConflict(dep);
      if (conflict) {
        conflicts.push({ package: dep, ...conflict });
      }
    }
    return conflicts;
  }

  /**
   * Get stats about preset coverage
   */
  getStats() {
    let pureCompute = 0, network = 0, framework = 0, database = 0;
    let buildTool = 0, testFramework = 0, native = 0, cloud = 0, other = 0;

    for (const [, preset] of this.presets) {
      switch (preset._category) {
        case 'pure_compute': pureCompute++; break;
        case 'network': network++; break;
        case 'framework': framework++; break;
        case 'database': database++; break;
        case 'build_tool': buildTool++; break;
        case 'test_framework': testFramework++; break;
        case 'native': native++; break;
        case 'cloud': cloud++; break;
        default: other++; break;
      }
    }

    return {
      total: this.presets.size,
      pureCompute,
      network,
      framework,
      database,
      buildTool,
      testFramework,
      native,
      cloud,
      other,
      conflicts: Object.keys(KNOWN_CONFLICTS).length,
    };
  }
}

module.exports = {
  PresetResolver,
  PURE_COMPUTE,
  NETWORK_PACKAGES,
  FRAMEWORKS,
  DATABASE_PACKAGES,
  BUILD_TOOLS,
  TEST_FRAMEWORKS,
  NATIVE_PACKAGES,
  NEXTJS_PACKAGES,
  CLOUD_SDKS,
  LOGGING_PACKAGES,
  MESSAGING_PACKAGES,
  KNOWN_CONFLICTS,
};
