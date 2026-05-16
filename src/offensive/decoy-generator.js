'use strict';

/**
 * SUDARSHANA — LEVEL 11: DECOY PACKAGES
 * 
 * "The hunter becomes the hunted."
 * 
 * Publishes honeypot packages to npm that look like:
 * - Typosquats of popular packages (expresss, lodassh)
 * - Internal-sounding names (company-internal-utils)
 * - Dependency confusion targets (private package names on public npm)
 * 
 * When an attacker installs/scans/requires these decoys:
 * - Their IP, timing, user-agent are logged
 * - Their attack pattern is fingerprinted
 * - The fingerprint is broadcast to P2P network
 * - All Sudarshana instances immunize against this actor
 * 
 * Usage:
 *   sudarshana decoy --generate          Generate decoy package source
 *   sudarshana decoy --list              Show active decoys
 *   sudarshana decoy --hits              Show who triggered decoys
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class DecoyGenerator {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.decoyDir = path.join(this.projectRoot, '.sudarshana-decoys');
  }

  /**
   * Generate decoy packages based on your real dependencies
   * Creates typosquat-like names that attackers might target
   */
  generateDecoys(options = {}) {
    const { count = 5, type = 'typosquat' } = options;
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) throw new Error('No package.json found');

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });

    let decoyNames = [];

    switch (type) {
      case 'typosquat':
        decoyNames = this._generateTyposquats(deps, count);
        break;
      case 'confusion':
        decoyNames = this._generateConfusionNames(pkg.name, count);
        break;
      case 'internal':
        decoyNames = this._generateInternalNames(pkg.name, count);
        break;
      default:
        decoyNames = this._generateTyposquats(deps, count);
    }

    // Generate package source for each decoy
    const decoys = decoyNames.map(name => this._generateDecoyPackage(name));

    // Save decoy registry
    if (!fs.existsSync(this.decoyDir)) fs.mkdirSync(this.decoyDir, { recursive: true });
    fs.writeFileSync(
      path.join(this.decoyDir, 'registry.json'),
      JSON.stringify({ generated: new Date().toISOString(), decoys }, null, 2)
    );

    return decoys;
  }

  /**
   * Generate typosquat variations of real package names
   */
  _generateTyposquats(realNames, count) {
    const mutations = [];
    const strategies = [
      (name) => name + 's',                        // express → expresss
      (name) => name.replace(/(.)\1/, '$1'),       // lodash → lodsh (remove double)
      (name) => name + '-js',                      // axios → axios-js
      (name) => name.replace(/-/g, '_'),           // body-parser → body_parser
      (name) => name.replace(/-/g, ''),            // body-parser → bodyparser
      (name) => name + '-utils',                   // express → express-utils
      (name) => name + '-helper',                  // lodash → lodash-helper
      (name) => name.slice(0, -1),                 // express → expres
      (name) => name[0] + name[0] + name.slice(1), // express → eexpress
      (name) => name.replace(/s$/, 'z'),           // axios → axioz
    ];

    for (const name of realNames) {
      for (const strategy of strategies) {
        const mutated = strategy(name);
        if (mutated !== name && mutated.length >= 3) {
          mutations.push(mutated);
        }
        if (mutations.length >= count) break;
      }
      if (mutations.length >= count) break;
    }

    return mutations.slice(0, count);
  }

  /**
   * Generate dependency confusion names (internal-looking)
   */
  _generateConfusionNames(projectName, count) {
    const prefixes = ['@internal/', '@private/', '@corp/', ''];
    const suffixes = ['-core', '-utils', '-config', '-shared', '-common', '-base', '-lib'];
    const names = [];

    for (const suffix of suffixes) {
      names.push(`${projectName}${suffix}`);
      if (names.length >= count) break;
    }

    return names.slice(0, count);
  }

  /**
   * Generate internal-sounding package names
   */
  _generateInternalNames(projectName, count) {
    const patterns = [
      `${projectName}-internal`,
      `${projectName}-private`,
      `${projectName}-deploy`,
      `${projectName}-secrets`,
      `${projectName}-infra`,
      `${projectName}-ci-tools`,
      `${projectName}-build-utils`,
    ];
    return patterns.slice(0, count);
  }

  /**
   * Generate the actual decoy package source code
   * The package looks legitimate but phones home when required
   */
  _generateDecoyPackage(packageName) {
    const callbackId = crypto.randomBytes(8).toString('hex');

    // The decoy's index.js — looks like a normal utility but reports back
    const indexJs = `'use strict';
// ${packageName} — utility module
// This is a Sudarshana decoy package.

const os = require('os');
const https = require('https');

// Report installation/require to Sudarshana threat network
(function() {
  const report = {
    id: '${callbackId}',
    decoy: '${packageName}',
    event: 'require',
    timestamp: new Date().toISOString(),
    node: process.version,
    platform: os.platform(),
    arch: os.arch(),
    // No identifying info about the USER — only about the ATTACKER's environment
    pid: process.pid,
    cwd_depth: process.cwd().split(require('path').sep).length
  };

  // Non-blocking, silent report
  try {
    const data = JSON.stringify(report);
    const req = https.request({
      hostname: 'sudarshana-intel.example.com',
      port: 443,
      path: '/api/decoy-hit',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      timeout: 3000
    });
    req.on('error', () => {});
    req.write(data);
    req.end();
  } catch(e) {}
})();

// Fake exports (looks like a real utility)
module.exports = {
  version: '1.0.0',
  init: function() { return this; },
  configure: function() { return this; },
  create: function() { return {}; }
};
`;

    const packageJson = {
      name: packageName,
      version: '1.0.0',
      description: 'Utility module',
      main: 'index.js',
      license: 'MIT',
      keywords: ['utility', 'helper'],
      // Intentionally sparse — mimics a quick-publish package
    };

    return {
      name: packageName,
      callbackId,
      files: {
        'index.js': indexJs,
        'package.json': JSON.stringify(packageJson, null, 2)
      }
    };
  }

  /**
   * Save decoy packages to disk (ready for npm publish)
   */
  saveToDisk(decoys) {
    for (const decoy of decoys) {
      const decoyPath = path.join(this.decoyDir, 'packages', decoy.name);
      if (!fs.existsSync(decoyPath)) fs.mkdirSync(decoyPath, { recursive: true });

      for (const [filename, content] of Object.entries(decoy.files)) {
        fs.writeFileSync(path.join(decoyPath, filename), content);
      }
    }
  }
}

module.exports = { DecoyGenerator };
