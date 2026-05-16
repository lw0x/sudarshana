'use strict';

/**
 * SUDARSHANA — LEARN MODE
 * 
 * "Run it. Forget it. It learns what's normal."
 * 
 * Learn mode observes your application over N runs and builds
 * the tightest possible security policy automatically.
 * 
 * How it works:
 * 1. First run: records EVERYTHING each package does
 * 2. Subsequent runs: refines the baseline (removes one-off noise)
 * 3. Generate: outputs the minimal policy that allows normal behavior
 * 
 * Usage:
 *   sudarshana learn -- node app.js          (observe & record)
 *   sudarshana learn --status                (show what's been learned)
 *   sudarshana learn --generate              (output tightest policy)
 *   sudarshana learn --generate --strict     (deny anything not observed)
 *   sudarshana learn --reset                 (clear all observations)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const LEARN_DIR = '.sudarshana-learn';

class LearnEngine {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.learnDir = path.join(this.projectRoot, LEARN_DIR);
    this.observations = {};
    this.runCount = 0;
    this._ensureDir();
    this._loadState();
  }

  _ensureDir() {
    if (!fs.existsSync(this.learnDir)) {
      fs.mkdirSync(this.learnDir, { recursive: true });
    }
  }

  _statePath() {
    return path.join(this.learnDir, 'observations.json');
  }

  _loadState() {
    const statePath = this._statePath();
    if (fs.existsSync(statePath)) {
      try {
        const data = JSON.parse(fs.readFileSync(statePath, 'utf8'));
        this.observations = data.observations || {};
        this.runCount = data.runCount || 0;
      } catch (e) {
        this.observations = {};
        this.runCount = 0;
      }
    }
  }

  _saveState() {
    const statePath = this._statePath();
    fs.writeFileSync(statePath, JSON.stringify({
      version: '1.0',
      lastUpdated: new Date().toISOString(),
      runCount: this.runCount,
      observations: this.observations
    }, null, 2));
  }

  /**
   * Record a single observation from runtime
   * @param {string} packageName - Which package performed the action
   * @param {string} category - env|fs_read|fs_write|network|dns|shell
   * @param {string} detail - Specific resource (env var name, file path, domain, etc.)
   */
  recordObservation(packageName, category, detail) {
    if (!this.observations[packageName]) {
      this.observations[packageName] = {
        env: {},
        fs_read: {},
        fs_write: {},
        network: {},
        dns: {},
        shell: {},
        first_seen: new Date().toISOString(),
        run_count: 0
      };
    }

    const pkg = this.observations[packageName];
    if (!pkg[category]) pkg[category] = {};

    if (!pkg[category][detail]) {
      pkg[category][detail] = { count: 0, first_seen: new Date().toISOString(), runs: [] };
    }

    pkg[category][detail].count++;
    if (!pkg[category][detail].runs.includes(this.runCount)) {
      pkg[category][detail].runs.push(this.runCount);
    }
  }

  /**
   * Start a new observation run
   */
  startRun() {
    this.runCount++;
    // Mark all packages as seen this run
    for (const pkg of Object.values(this.observations)) {
      pkg.run_count = (pkg.run_count || 0) + 1;
    }
  }

  /**
   * End current run and persist
   */
  endRun() {
    this._saveState();
  }

  /**
   * Generate the tightest possible policy from observations
   * @param {Object} options - { strict: boolean, minRuns: number }
   */
  generatePolicy(options = {}) {
    const { strict = false, minRuns = 1 } = options;
    const totalRuns = this.runCount;

    const policies = {
      '_application_': {
        trust_level: 'system',
        env_visible: ['*'],
        fs_read: ['*'],
        fs_write: ['*'],
        network: ['*'],
        shell: ['*']
      }
    };

    for (const [packageName, data] of Object.entries(this.observations)) {
      if (packageName === '_application_') continue;

      const policy = {
        trust_level: 'limited'
      };

      // ENV: only vars accessed in >= minRuns runs
      const envVars = Object.entries(data.env || {})
        .filter(([_, info]) => info.runs.length >= minRuns)
        .map(([varName]) => varName);
      policy.env_visible = envVars.length > 0 ? envVars : [];

      // FS READ: collapse to directory patterns
      const fsReads = Object.entries(data.fs_read || {})
        .filter(([_, info]) => info.runs.length >= minRuns)
        .map(([filePath]) => filePath);
      policy.fs_read = this._collapsePathsToPatterns(fsReads);

      // FS WRITE: same treatment
      const fsWrites = Object.entries(data.fs_write || {})
        .filter(([_, info]) => info.runs.length >= minRuns)
        .map(([filePath]) => filePath);
      policy.fs_write = strict ? [] : this._collapsePathsToPatterns(fsWrites);

      // NETWORK: extract unique domains
      const netDomains = Object.entries(data.network || {})
        .filter(([_, info]) => info.runs.length >= minRuns)
        .map(([domain]) => domain);
      policy.network = this._collapseDomains(netDomains);

      // DNS: extract unique domains
      const dnsDomains = Object.entries(data.dns || {})
        .filter(([_, info]) => info.runs.length >= minRuns)
        .map(([domain]) => domain);
      // Merge DNS into network policy
      policy.network = [...new Set([...policy.network, ...this._collapseDomains(dnsDomains)])];

      // SHELL: list allowed commands
      const shellCmds = Object.entries(data.shell || {})
        .filter(([_, info]) => info.runs.length >= minRuns)
        .map(([cmd]) => cmd);
      policy.shell = strict ? [] : shellCmds;

      // Determine trust level based on capabilities
      const totalCapabilities = envVars.length + fsReads.length + netDomains.length + shellCmds.length;
      if (totalCapabilities === 0) {
        policy.trust_level = 'trusted';
        policy._comment = 'Pure compute — zero capabilities observed across ' + totalRuns + ' runs';
      } else if (shellCmds.length > 0) {
        policy.trust_level = 'limited';
        policy._comment = 'Shell access observed — review if necessary';
      } else {
        policy._comment = 'Auto-learned from ' + totalRuns + ' observation runs';
      }

      policies[packageName] = policy;
    }

    return {
      $schema: 'https://sudarshana.dev/config-schema.json',
      $generated: new Date().toISOString(),
      $generator: 'sudarshana learn --generate',
      $learnStats: {
        totalRuns: this.runCount,
        packagesObserved: Object.keys(this.observations).length,
        mode: strict ? 'strict' : 'standard'
      },
      mode: strict ? 'lockdown' : 'enforce',
      enableHoneypots: true,
      policies
    };
  }

  /**
   * Collapse individual file paths into directory patterns
   * e.g., ['/app/src/a.js', '/app/src/b.js'] → ['./src/*']
   */
  _collapsePathsToPatterns(paths) {
    if (paths.length === 0) return [];

    const dirs = {};
    for (const p of paths) {
      const dir = path.dirname(p);
      if (!dirs[dir]) dirs[dir] = 0;
      dirs[dir]++;
    }

    const patterns = [];
    for (const [dir, count] of Object.entries(dirs)) {
      if (count >= 3) {
        // 3+ files from same dir → use wildcard
        patterns.push(dir + '/*');
      } else {
        // Few files → list individually
        const filesInDir = paths.filter(p => path.dirname(p) === dir);
        patterns.push(...filesInDir);
      }
    }

    return [...new Set(patterns)];
  }

  /**
   * Collapse domains into wildcard patterns where possible
   * e.g., ['a.api.com', 'b.api.com', 'c.api.com'] → ['*.api.com']
   */
  _collapseDomains(domains) {
    if (domains.length === 0) return [];

    const suffixCount = {};
    for (const domain of domains) {
      const parts = domain.split('.');
      if (parts.length >= 3) {
        const suffix = parts.slice(1).join('.');
        if (!suffixCount[suffix]) suffixCount[suffix] = [];
        suffixCount[suffix].push(domain);
      }
    }

    const result = new Set(domains);
    for (const [suffix, matchedDomains] of Object.entries(suffixCount)) {
      if (matchedDomains.length >= 3) {
        // 3+ subdomains of same parent → wildcard
        for (const d of matchedDomains) result.delete(d);
        result.add('*.' + suffix);
      }
    }

    return [...result];
  }

  /**
   * Get human-readable status of what's been learned
   */
  getStatus() {
    const lines = [];
    lines.push('');
    lines.push('🧠 SUDARSHANA — Learn Mode Status');
    lines.push('─'.repeat(50));
    lines.push(`  Observation runs:  ${this.runCount}`);
    lines.push(`  Packages observed: ${Object.keys(this.observations).length}`);
    lines.push(`  Data stored in:    ${this.learnDir}`);
    lines.push('');

    if (Object.keys(this.observations).length === 0) {
      lines.push('  No observations yet. Run:');
      lines.push('  sudarshana learn -- node app.js');
      lines.push('');
      return lines.join('\n');
    }

    lines.push('  Package Capabilities Observed:');
    lines.push('  ' + '─'.repeat(48));

    for (const [pkgName, data] of Object.entries(this.observations)) {
      const envCount = Object.keys(data.env || {}).length;
      const fsReadCount = Object.keys(data.fs_read || {}).length;
      const fsWriteCount = Object.keys(data.fs_write || {}).length;
      const netCount = Object.keys(data.network || {}).length;
      const dnsCount = Object.keys(data.dns || {}).length;
      const shellCount = Object.keys(data.shell || {}).length;

      const caps = [];
      if (envCount > 0) caps.push(`env:${envCount}`);
      if (fsReadCount > 0) caps.push(`fs_r:${fsReadCount}`);
      if (fsWriteCount > 0) caps.push(`fs_w:${fsWriteCount}`);
      if (netCount > 0) caps.push(`net:${netCount}`);
      if (dnsCount > 0) caps.push(`dns:${dnsCount}`);
      if (shellCount > 0) caps.push(`sh:${shellCount}`);

      const capsStr = caps.length > 0 ? caps.join(', ') : 'pure compute (zero access)';
      lines.push(`  ${pkgName.padEnd(30)} ${capsStr}`);
    }

    lines.push('');
    lines.push('  Ready to generate policy? Run:');
    lines.push('  sudarshana learn --generate');
    lines.push('');
    return lines.join('\n');
  }

  /**
   * Reset all learned data
   */
  reset() {
    this.observations = {};
    this.runCount = 0;
    const statePath = this._statePath();
    if (fs.existsSync(statePath)) fs.unlinkSync(statePath);
  }
}

/**
 * Runtime hooks for learn mode — attaches to the existing sandbox
 * to passively record what each package does
 */
class LearnModeHooks {
  constructor(learnEngine) {
    this.engine = learnEngine;
    this.engine.startRun();
  }

  onEnvAccess(packageName, varName) {
    this.engine.recordObservation(packageName, 'env', varName);
  }

  onFsRead(packageName, filePath) {
    this.engine.recordObservation(packageName, 'fs_read', filePath);
  }

  onFsWrite(packageName, filePath) {
    this.engine.recordObservation(packageName, 'fs_write', filePath);
  }

  onNetwork(packageName, domain) {
    this.engine.recordObservation(packageName, 'network', domain);
  }

  onDns(packageName, hostname) {
    this.engine.recordObservation(packageName, 'dns', hostname);
  }

  onShell(packageName, command) {
    this.engine.recordObservation(packageName, 'shell', command);
  }

  finalize() {
    this.engine.endRun();
  }
}

module.exports = { LearnEngine, LearnModeHooks };
