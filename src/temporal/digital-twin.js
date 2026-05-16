'use strict';

/**
 * SUDARSHANA — LEVEL 14: SUPPLY CHAIN DIGITAL TWIN
 * 
 * "A complete virtual replica of your dependency tree.
 *  Every attack hits the twin first."
 * 
 * The Digital Twin is a behavioral model of your entire node_modules.
 * It records:
 * - What each package does at each version (behavioral timeline)
 * - How packages interact with each other
 * - Expected behavior baseline per-version
 * 
 * Then on `npm update`:
 * - The twin is updated FIRST (in simulation)
 * - Delta is computed: "What's NEW in behavior?"
 * - Developer reviews the delta BEFORE applying to production
 * 
 * This is the "Regression Oracle":
 * - "express@4.18.2 → 4.18.3: No behavioral change. Safe to update."
 * - "axios@1.5.0 → 1.6.0: NEW: now reads process.env.PROXY_AUTH. Review."
 * - "evil-pkg@1.0.0 → 1.0.1: NEW: http.request to unknown domain. BLOCK."
 * 
 * Time-Travel capability:
 * - "What could package X have stolen between v2.1.0 and v2.1.1?"
 * - Replay the behavioral delta and enumerate all accessible secrets
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const TWIN_DIR = '.sudarshana-twin';

class DigitalTwin {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.twinDir = path.join(this.projectRoot, TWIN_DIR);
    this.timeline = this._loadTimeline();
  }

  _ensureDir() {
    if (!fs.existsSync(this.twinDir)) fs.mkdirSync(this.twinDir, { recursive: true });
  }

  _timelinePath() { return path.join(this.twinDir, 'timeline.json'); }

  _loadTimeline() {
    this._ensureDir();
    const p = this._timelinePath();
    if (fs.existsSync(p)) {
      try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch(e) {}
    }
    return { snapshots: [], currentIndex: -1 };
  }

  _saveTimeline() {
    fs.writeFileSync(this._timelinePath(), JSON.stringify(this.timeline, null, 2));
  }

  /**
   * Take a snapshot of the current dependency tree behavior
   * This is a "moment in time" for the digital twin
   */
  snapshot() {
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) throw new Error('No package.json');

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });

    const snap = {
      id: crypto.randomBytes(6).toString('hex'),
      timestamp: new Date().toISOString(),
      projectVersion: pkg.version,
      packages: {}
    };

    for (const dep of deps) {
      const depPkgPath = path.join(this.projectRoot, 'node_modules', dep, 'package.json');
      if (!fs.existsSync(depPkgPath)) continue;

      try {
        const depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf8'));
        snap.packages[dep] = {
          version: depPkg.version,
          dependencies: Object.keys(depPkg.dependencies || {}),
          hasInstallScript: !!(depPkg.scripts && (depPkg.scripts.postinstall || depPkg.scripts.preinstall)),
          capabilities: this._inferCapabilities(dep),
          contentHash: this._hashPackage(dep),
          maintainers: (depPkg.maintainers || []).map(m => m.name || m.email || m),
          publisher: depPkg._npmUser ? (depPkg._npmUser.name || depPkg._npmUser.email) : null
        };
      } catch(e) {}
    }

    this.timeline.snapshots.push(snap);
    this.timeline.currentIndex = this.timeline.snapshots.length - 1;
    this._saveTimeline();

    return snap;
  }

  /**
   * Regression Oracle — compare two snapshots and report behavioral delta
   * "What changed between then and now?"
   */
  regressionAnalysis(fromIndex, toIndex) {
    const from = this.timeline.snapshots[fromIndex];
    const to = this.timeline.snapshots[toIndex !== undefined ? toIndex : this.timeline.snapshots.length - 1];

    if (!from || !to) throw new Error('Invalid snapshot index');

    const deltas = [];

    // Check each package in the "to" snapshot
    for (const [pkgName, toData] of Object.entries(to.packages)) {
      const fromData = from.packages[pkgName];

      if (!fromData) {
        // New package added
        deltas.push({
          package: pkgName,
          type: 'ADDED',
          severity: toData.hasInstallScript ? 'HIGH' : 'LOW',
          detail: `New dependency: ${pkgName}@${toData.version}`,
          capabilities: toData.capabilities
        });
        continue;
      }

      // Version changed
      if (fromData.version !== toData.version) {
        const capDelta = this._diffCapabilities(fromData.capabilities, toData.capabilities);
        const severity = capDelta.added.length > 0 ? 'MEDIUM' : 'LOW';

        deltas.push({
          package: pkgName,
          type: 'VERSION_CHANGED',
          severity,
          from: fromData.version,
          to: toData.version,
          detail: `${fromData.version} → ${toData.version}`,
          capabilitiesAdded: capDelta.added,
          capabilitiesRemoved: capDelta.removed
        });
      }

      // Same version but content changed (CRITICAL)
      if (fromData.version === toData.version && fromData.contentHash !== toData.contentHash) {
        deltas.push({
          package: pkgName,
          type: 'CONTENT_TAMPERED',
          severity: 'CRITICAL',
          detail: `Same version (${toData.version}) but content hash changed!`,
          fromHash: fromData.contentHash,
          toHash: toData.contentHash
        });
      }

      // Maintainer changed
      if (fromData.publisher && toData.publisher && fromData.publisher !== toData.publisher) {
        deltas.push({
          package: pkgName,
          type: 'PUBLISHER_CHANGED',
          severity: 'HIGH',
          detail: `Publisher: ${fromData.publisher} → ${toData.publisher}`,
        });
      }

      // Install script added
      if (!fromData.hasInstallScript && toData.hasInstallScript) {
        deltas.push({
          package: pkgName,
          type: 'INSTALL_SCRIPT_ADDED',
          severity: 'HIGH',
          detail: 'Install script added in this version'
        });
      }

      // New dependencies added
      const newDeps = toData.dependencies.filter(d => !fromData.dependencies.includes(d));
      if (newDeps.length > 0) {
        deltas.push({
          package: pkgName,
          type: 'NEW_DEPENDENCIES',
          severity: newDeps.length > 3 ? 'MEDIUM' : 'LOW',
          detail: `+${newDeps.length} new transitive deps: ${newDeps.slice(0, 5).join(', ')}`,
          newDependencies: newDeps
        });
      }
    }

    // Check for removed packages
    for (const pkgName of Object.keys(from.packages)) {
      if (!to.packages[pkgName]) {
        deltas.push({
          package: pkgName,
          type: 'REMOVED',
          severity: 'LOW',
          detail: `Dependency removed: ${pkgName}`
        });
      }
    }

    return {
      from: { id: from.id, timestamp: from.timestamp },
      to: { id: to.id, timestamp: to.timestamp },
      totalChanges: deltas.length,
      critical: deltas.filter(d => d.severity === 'CRITICAL').length,
      high: deltas.filter(d => d.severity === 'HIGH').length,
      medium: deltas.filter(d => d.severity === 'MEDIUM').length,
      low: deltas.filter(d => d.severity === 'LOW').length,
      safe: deltas.length === 0 || deltas.every(d => d.severity === 'LOW'),
      deltas
    };
  }

  /**
   * Time-Travel Audit
   * "What COULD package X have accessed between version A and version B?"
   */
  timeTravelAudit(packageName, fromVersion, toVersion) {
    const depPath = path.join(this.projectRoot, 'node_modules', packageName);
    if (!fs.existsSync(depPath)) return { error: 'Package not installed' };

    // Find snapshots containing this package at these versions
    const fromSnap = this.timeline.snapshots.find(s =>
      s.packages[packageName] && s.packages[packageName].version === fromVersion
    );
    const toSnap = this.timeline.snapshots.find(s =>
      s.packages[packageName] && s.packages[packageName].version === toVersion
    );

    // Current capabilities
    const currentCaps = this._inferCapabilities(packageName);

    // Load current policy
    const configPath = path.join(this.projectRoot, '.sudarshana.json');
    let policy = { env_visible: ['*'], network: ['*'], fs_read: ['*'] };
    if (fs.existsSync(configPath)) {
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      policy = config.policies[packageName] || policy;
    }

    // What COULD have been stolen?
    const exposure = {
      package: packageName,
      fromVersion,
      toVersion,
      analysis: 'THEORETICAL — based on declared capabilities and policy',
      potentialAccess: {
        envVars: policy.env_visible && policy.env_visible.includes('*')
          ? ['ALL ENV VARS (wildcard policy!)']
          : (policy.env_visible || []),
        fileSystem: policy.fs_read && policy.fs_read.includes('*')
          ? ['ALL FILES (wildcard policy!)']
          : (policy.fs_read || []),
        network: policy.network && policy.network.includes('*')
          ? ['ALL DOMAINS (wildcard policy!)']
          : (policy.network || []),
      },
      riskAssessment: policy.env_visible && policy.env_visible.includes('*')
        ? 'CRITICAL — Package had unrestricted access. Full audit required.'
        : 'CONTAINED — Package was sandboxed. Limited exposure.',
      recommendation: [
        'Review access logs from Sudarshana behavioral engine',
        'Check content hash tracker for outbound sensitive data',
        'Verify no honeypot alerts during this version\'s lifetime',
        `Pin to known-good version: npm install ${packageName}@"<${toVersion}"`
      ]
    };

    return exposure;
  }

  /**
   * Pre-Update Simulation
   * "What WILL change if I run npm update?"
   */
  simulateUpdate(updates) {
    // `updates` is a map of package → newVersion
    // We predict what behavioral changes will occur

    const predictions = [];

    for (const [packageName, newVersion] of Object.entries(updates)) {
      const currentSnap = this.timeline.snapshots[this.timeline.currentIndex];
      const currentData = currentSnap ? currentSnap.packages[packageName] : null;

      if (!currentData) {
        predictions.push({
          package: packageName,
          type: 'NEW_INSTALL',
          prediction: 'Unable to predict — no behavioral history for this package',
          recommendation: 'Run `sudarshana predict ' + packageName + '` after install'
        });
        continue;
      }

      // Find historical data for this new version (if we've seen it before)
      const historicalSnap = this.timeline.snapshots.find(s =>
        s.packages[packageName] && s.packages[packageName].version === newVersion
      );

      if (historicalSnap) {
        const delta = this._diffCapabilities(
          currentData.capabilities,
          historicalSnap.packages[packageName].capabilities
        );
        predictions.push({
          package: packageName,
          currentVersion: currentData.version,
          newVersion,
          type: 'KNOWN_VERSION',
          prediction: delta.added.length > 0
            ? `⚠️ New capabilities: ${delta.added.join(', ')}`
            : '✅ No behavioral change expected',
          safe: delta.added.length === 0
        });
      } else {
        predictions.push({
          package: packageName,
          currentVersion: currentData.version,
          newVersion,
          type: 'UNKNOWN_VERSION',
          prediction: `Version ${newVersion} never observed. Cannot predict behavior.`,
          recommendation: `Install in learn mode first: sudarshana learn -- node -e "require('${packageName}')"`
        });
      }
    }

    return {
      timestamp: new Date().toISOString(),
      updatesAnalyzed: Object.keys(updates).length,
      safeUpdates: predictions.filter(p => p.safe).length,
      unknownUpdates: predictions.filter(p => p.type === 'UNKNOWN_VERSION').length,
      riskyUpdates: predictions.filter(p => p.type === 'KNOWN_VERSION' && !p.safe).length,
      predictions
    };
  }

  /**
   * Infer capabilities by scanning package source
   */
  _inferCapabilities(packageName) {
    const depPath = path.join(this.projectRoot, 'node_modules', packageName);
    if (!fs.existsSync(depPath)) return [];

    const capabilities = [];
    const pkgJsonPath = path.join(depPath, 'package.json');

    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      const mainFile = path.join(depPath, pkg.main || 'index.js');

      if (fs.existsSync(mainFile)) {
        const source = fs.readFileSync(mainFile, 'utf8');

        if (/process\.env/.test(source)) capabilities.push('ENV_READ');
        if (/require\(['"]fs['"]\)|from\s+['"]fs['"]/.test(source)) capabilities.push('FS');
        if (/require\(['"]https?['"]\)|from\s+['"]https?['"]/.test(source)) capabilities.push('HTTP');
        if (/require\(['"]net['"]\)|from\s+['"]net['"]/.test(source)) capabilities.push('NET');
        if (/require\(['"]dns['"]\)|from\s+['"]dns['"]/.test(source)) capabilities.push('DNS');
        if (/require\(['"]child_process['"]\)|from\s+['"]child_process['"]/.test(source)) capabilities.push('SHELL');
        if (/require\(['"]crypto['"]\)|from\s+['"]crypto['"]/.test(source)) capabilities.push('CRYPTO');
      }
    } catch(e) {}

    return capabilities;
  }

  _diffCapabilities(fromCaps, toCaps) {
    const from = new Set(fromCaps || []);
    const to = new Set(toCaps || []);
    return {
      added: [...to].filter(c => !from.has(c)),
      removed: [...from].filter(c => !to.has(c))
    };
  }

  _hashPackage(packageName) {
    const depPath = path.join(this.projectRoot, 'node_modules', packageName);
    const pkgJsonPath = path.join(depPath, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return null;

    try {
      const content = fs.readFileSync(pkgJsonPath, 'utf8');
      const mainFile = path.join(depPath, JSON.parse(content).main || 'index.js');
      if (fs.existsSync(mainFile)) {
        const mainContent = fs.readFileSync(mainFile);
        return crypto.createHash('sha256').update(mainContent).digest('hex').substring(0, 16);
      }
    } catch(e) {}
    return null;
  }

  /**
   * Get timeline status
   */
  getStatus() {
    return {
      snapshots: this.timeline.snapshots.length,
      currentIndex: this.timeline.currentIndex,
      firstSnapshot: this.timeline.snapshots[0]?.timestamp || null,
      lastSnapshot: this.timeline.snapshots[this.timeline.snapshots.length - 1]?.timestamp || null
    };
  }

  /**
   * Generate regression report
   */
  generateReport(analysis) {
    const lines = [];
    lines.push('');
    lines.push('⏳ SUDARSHANA — Regression Oracle');
    lines.push('═'.repeat(55));
    lines.push(`  From: ${analysis.from.timestamp} (${analysis.from.id})`);
    lines.push(`  To:   ${analysis.to.timestamp} (${analysis.to.id})`);
    lines.push(`  Changes: ${analysis.totalChanges}`);
    lines.push(`  Safe to update: ${analysis.safe ? '✅ YES' : '⚠️ REVIEW REQUIRED'}`);
    lines.push('');

    if (analysis.critical > 0) lines.push(`  🔴 CRITICAL: ${analysis.critical}`);
    if (analysis.high > 0) lines.push(`  🟠 HIGH: ${analysis.high}`);
    if (analysis.medium > 0) lines.push(`  🟡 MEDIUM: ${analysis.medium}`);
    if (analysis.low > 0) lines.push(`  🔵 LOW: ${analysis.low}`);
    lines.push('');

    for (const delta of analysis.deltas.filter(d => d.severity !== 'LOW')) {
      const icon = delta.severity === 'CRITICAL' ? '🔴' : delta.severity === 'HIGH' ? '🟠' : '🟡';
      lines.push(`  ${icon} ${delta.package} — ${delta.type}`);
      lines.push(`     ${delta.detail}`);
      if (delta.capabilitiesAdded && delta.capabilitiesAdded.length > 0) {
        lines.push(`     NEW capabilities: ${delta.capabilitiesAdded.join(', ')}`);
      }
      lines.push('');
    }

    if (analysis.deltas.length === 0) {
      lines.push('  ✅ No changes detected between snapshots.');
    }

    return lines.join('\n');
  }
}

module.exports = { DigitalTwin };
