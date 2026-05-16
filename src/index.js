'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  SUDARSHANA v2.0 — THE REALITY ENFORCER                      ║
 * ║                                                              ║
 * ║  "The gun doesn't exist in their reality."                    ║
 * ║                                                              ║
 * ║  Not a detector. Not a blocker. A REALITY CONTROLLER.         ║
 * ║  Each package lives in its own universe where malicious       ║
 * ║  actions are physically impossible — not blocked, but         ║
 * ║  non-existent.                                                ║
 * ╚══════════════════════════════════════════════════════════════╝
 * 
 * Usage (must be loaded FIRST via --require):
 *   node --require ./sudarshana/src/index-v2.js your-app.js
 * 
 * Or in code (as early as possible):
 *   require('./sudarshana/src/index.js');
 */

const path = require('path');
const fs = require('fs');
const { StealthLoader } = require('./stealth/stealth-loader');
const { BehavioralEngine } = require('./kernel/behavioral-engine');
const { createVirtualEnvWithHoneypots } = require('./virtual/virtual-env');

// ══════════════════════════════════════════════════════════════════
// INITIALIZATION — happens immediately on require()
// ══════════════════════════════════════════════════════════════════

let _instance = null;

function initialize(config = null) {
  if (_instance) return _instance;

  // Load config from file or use defaults
  if (!config) {
    config = loadConfig();
  }

  // 1. Create behavioral engine (the brain)
  const behavioral = new BehavioralEngine({
    onCritical: (violation) => {
      handleCriticalViolation(violation, config);
    }
  });

  // 2. Create stealth loader (the invisibility cloak)
  const loader = new StealthLoader({
    projectRoot: config.projectRoot || process.cwd(),
    policies: config.policies || {},
    configPath: config._configPath
  });

  // 3. Install the stealth loader (intercepts all require() calls)
  loader.install();

  // 4. Override process.env globally with honeypot-enhanced virtual env
  // The application's own code gets full access; packages get sandboxed
  // This is done per-package in the stealth loader, but we set up honeypots here
  if (config.enableHoneypots !== false) {
    injectHoneypots(behavioral);
  }

  // 5. Freeze critical globals to prevent prototype pollution
  freezeGlobals();

  // 6. Register cleanup handler
  process.on('exit', () => {
    loader._flushSignals();
    generateReport(loader, behavioral, config);
  });

  process.on('SIGTERM', () => { loader.destroy(); process.exit(0); });
  process.on('SIGINT', () => { loader.destroy(); process.exit(0); });

  _instance = { loader, behavioral, config };
  return _instance;
}

/**
 * Load configuration from .sudarshana.json or sudarshana.config.js
 */
function loadConfig() {
  const cwd = process.cwd();
  const configPaths = [
    path.join(cwd, '.sudarshana.json'),
    path.join(cwd, 'sudarshana.config.json'),
    path.join(cwd, 'sudarshana.config.js')
  ];

  for (const configPath of configPaths) {
    try {
      if (fs.existsSync(configPath)) {
        const config = configPath.endsWith('.js')
          ? require(configPath)
          : JSON.parse(fs.readFileSync(configPath, 'utf8'));
        
        config._configPath = configPath;
        return config;
      }
    } catch (e) {
      // Config load failure — use defaults (don't crash)
    }
  }

  // No config found — use maximum security defaults
  return {
    mode: 'enforce',
    projectRoot: cwd,
    enableHoneypots: true,
    policies: {},
    onViolation: 'log', // 'log' | 'kill' | 'webhook'
    reportPath: path.join(cwd, '.sudarshana-report.json'),
    _configPath: null
  };
}

/**
 * Inject honeypot environment variables that trigger on access
 */
function injectHoneypots(behavioral) {
  const crypto = require('crypto');
  
  // These look like real secrets — any package that reads them is malicious
  const honeypotVars = {
    'AWS_SECRET_ACCESS_KEY_BACKUP': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY' + crypto.randomBytes(4).toString('hex'),
    'DATABASE_ADMIN_PASSWORD': 'admin_' + crypto.randomBytes(12).toString('base64'),
    'GITHUB_PERSONAL_TOKEN_OLD': 'ghp_' + crypto.randomBytes(20).toString('hex'),
    'STRIPE_SECRET_KEY_LIVE': 'sk_live_' + crypto.randomBytes(24).toString('base64'),
    'INTERNAL_MASTER_KEY': 'mk_' + crypto.randomBytes(16).toString('hex'),
  };

  // Set them in the real env (they'll be visible to packages that enumerate)
  for (const [key, value] of Object.entries(honeypotVars)) {
    process.env[key] = value;
  }

  // Register all honeypot values for content tracking
  for (const [key, value] of Object.entries(honeypotVars)) {
    const hash = crypto.createHash('sha256').update(value).digest('hex').substring(0, 16);
    behavioral.contentHashes.set(hash, {
      source: 'honeypot',
      target: key,
      package: '_SYSTEM_',
      timestamp: Date.now()
    });
  }
}

/**
 * Freeze critical Object prototypes to prevent pollution attacks
 */
function freezeGlobals() {
  // Freeze Object.prototype to prevent pollution
  Object.freeze(Object.prototype);
  Object.freeze(Array.prototype);
  Object.freeze(Function.prototype);
  Object.freeze(String.prototype);
  Object.freeze(Number.prototype);
  Object.freeze(Boolean.prototype);
  Object.freeze(RegExp.prototype);

  // Prevent defineProperty abuse
  const originalDefineProperty = Object.defineProperty;
  Object.defineProperty = function(obj, prop, desc) {
    // Allow on non-prototype objects (normal usage)
    if (obj === Object.prototype || obj === Array.prototype || obj === Function.prototype) {
      // Prototype modification attempt!
      throw new TypeError(`Cannot define property ${String(prop)} on frozen prototype`);
    }
    return originalDefineProperty.call(Object, obj, prop, desc);
  };
}

/**
 * Handle critical security violation
 */
function handleCriticalViolation(violation, config) {
  const message = `
[SUDARSHANA CRITICAL] Security violation detected!
  Package: ${violation.package}
  Rule: ${violation.rule}
  ${violation.description}
  Time: ${new Date(violation.timestamp).toISOString()}
`;

  // Always log to stderr
  process.stderr.write(message + '\n');

  // Write to signal file immediately
  try {
    const signalFile = path.join(process.cwd(), '.sudarshana-signals.ndjson');
    fs.appendFileSync(signalFile, JSON.stringify(violation) + '\n');
  } catch (e) {}

  // Action based on config
  switch (config.onViolation) {
    case 'kill':
      process.stderr.write('[SUDARSHANA] KILLING PROCESS — critical violation.\n');
      process.exit(99);
      break;

    case 'webhook':
      if (config.webhookUrl) {
        try {
          const https = require('https');
          const url = new URL(config.webhookUrl);
          const req = https.request({
            hostname: url.hostname,
            port: url.port || 443,
            path: url.pathname,
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          req.write(JSON.stringify(violation));
          req.end();
        } catch (e) {}
      }
      break;

    case 'log':
    default:
      // Already logged above
      break;
  }
}

/**
 * Generate final report on exit
 */
function generateReport(loader, behavioral, config) {
  const report = {
    version: '2.0.0',
    architecture: 'missile',
    timestamp: new Date().toISOString(),
    mode: config.mode || 'enforce',
    violations: behavioral.getViolations(),
    signals: loader.signals,
    packageBehaviors: {},
    summary: {
      totalPackagesMonitored: loader.virtualCache.size,
      criticalViolations: 0,
      highViolations: 0,
      honeypotTriggered: false
    }
  };

  // Count violations by severity
  for (const v of report.violations) {
    if (v.severity === 'CRITICAL') report.summary.criticalViolations++;
    if (v.severity === 'HIGH') report.summary.highViolations++;
    if (v.rule === 'HONEYPOT_ACCESS') report.summary.honeypotTriggered = true;
  }

  // Write report
  const reportPath = config.reportPath || path.join(process.cwd(), '.sudarshana-report.json');
  try {
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  } catch (e) {
    process.stderr.write(`[SUDARSHANA] Could not write report: ${e.message}\n`);
  }

  // Print summary to stderr
  if (report.violations.length > 0) {
    process.stderr.write(`\n[SUDARSHANA] ${report.violations.length} security violations detected.\n`);
    process.stderr.write(`  Critical: ${report.summary.criticalViolations}\n`);
    process.stderr.write(`  High: ${report.summary.highViolations}\n`);
    if (report.summary.honeypotTriggered) {
      process.stderr.write(`  🚨 HONEYPOT TRIGGERED — definitive malicious activity!\n`);
    }
    process.stderr.write(`  Report: ${reportPath}\n\n`);
  }

  // Exit code based on violations
  if (report.summary.criticalViolations > 0 || report.summary.honeypotTriggered) {
    process.exitCode = 99;
  }
}

// ══════════════════════════════════════════════════════════════════
// AUTO-INITIALIZE when required
// ══════════════════════════════════════════════════════════════════
const instance = initialize();

// Export minimal API (don't expose internals!)
module.exports = Object.freeze({
  version: '2.0.0',
  architecture: 'missile',

  // Get current violation count (for testing)
  getViolationCount: () => instance.behavioral.getViolations().length,

  // Get violations (for reporting integrations)  
  getViolations: () => [...instance.behavioral.getViolations()],

  // Manual shutdown
  destroy: () => instance.loader.destroy()
});
