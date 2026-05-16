'use strict';

/**
 * SUDARSHANA — DRIFT DETECTION
 * 
 * "The package you trusted yesterday is not the package you have today."
 * 
 * Drift detection catches the #1 real-world attack vector:
 * A legitimate package gets compromised in a patch/minor update.
 * 
 * How it works:
 * 1. Snapshots each package's behavioral fingerprint (what it accesses)
 * 2. On next run, compares against the snapshot
 * 3. NEW capabilities = alert (package suddenly needs network? 🚨)
 * 
 * Usage:
 *   sudarshana snapshot                   (save current behavior baseline)
 *   sudarshana drift                      (compare current vs snapshot)
 *   sudarshana diff express@4.18.2 express@4.18.3  (compare two versions)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SNAPSHOT_DIR = '.sudarshana-snapshots';

class DriftDetector {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.snapshotDir = path.join(this.projectRoot, SNAPSHOT_DIR);
  }

  /**
   * Create a behavioral snapshot of the current node_modules
   * Analyzes package.json + source code of each dependency
   */
  snapshot() {
    const nodeModulesPath = path.join(this.projectRoot, 'node_modules');
    if (!fs.existsSync(nodeModulesPath)) {
      throw new Error('No node_modules found. Run npm install first.');
    }

    if (!fs.existsSync(this.snapshotDir)) {
      fs.mkdirSync(this.snapshotDir, { recursive: true });
    }

    const projectPkg = JSON.parse(
      fs.readFileSync(path.join(this.projectRoot, 'package.json'), 'utf8')
    );
    const deps = Object.keys({
      ...projectPkg.dependencies,
      ...projectPkg.devDependencies
    });

    const snapshot = {
      timestamp: new Date().toISOString(),
      nodeVersion: process.version,
      totalDeps: deps.length,
      packages: {}
    };

    for (const depName of deps) {
      const depPath = path.join(nodeModulesPath, depName);
      if (!fs.existsSync(depPath)) continue;

      snapshot.packages[depName] = this._analyzePackage(depName, depPath);
    }

    // Save snapshot
    const snapshotPath = path.join(this.snapshotDir, 'latest.json');
    const previousPath = path.join(this.snapshotDir, 'previous.json');

    // Rotate: current → previous
    if (fs.existsSync(snapshotPath)) {
      fs.copyFileSync(snapshotPath, previousPath);
    }

    fs.writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2));

    return snapshot;
  }

  /**
   * Analyze a single package for its behavioral fingerprint
   */
  _analyzePackage(packageName, packagePath) {
    const pkgJsonPath = path.join(packagePath, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return { error: 'no package.json' };

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));

    // Get content hash of main entry point
    const mainFile = pkg.main || 'index.js';
    const mainPath = path.join(packagePath, mainFile);
    let contentHash = null;
    if (fs.existsSync(mainPath)) {
      const content = fs.readFileSync(mainPath);
      contentHash = crypto.createHash('sha256').update(content).digest('hex').substring(0, 16);
    }

    // Static analysis — what built-in modules does it require/import?
    const capabilities = this._detectCapabilities(packagePath);

    // Check for install scripts
    const hasInstallScripts = !!(
      pkg.scripts &&
      (pkg.scripts.preinstall || pkg.scripts.install || pkg.scripts.postinstall)
    );

    return {
      version: pkg.version,
      contentHash,
      capabilities,
      hasInstallScripts,
      dependencies: Object.keys(pkg.dependencies || {}),
      maintainers: (pkg.maintainers || []).map(m => typeof m === 'string' ? m : m.name || m.email),
      publishedBy: pkg._npmUser ? pkg._npmUser.name : null,
      hasNativeAddon: !!pkg.gypfile || !!(pkg.scripts && pkg.scripts.install && pkg.scripts.install.includes('node-gyp'))
    };
  }

  /**
   * Detect what built-in Node.js modules a package uses (static scan)
   */
  _detectCapabilities(packagePath) {
    const caps = {
      fs: false,
      net: false,
      http: false,
      https: false,
      dns: false,
      child_process: false,
      crypto: false,
      os: false,
      process_env: false
    };

    // Scan JS files (top level + lib/ only, not deep)
    const scanDirs = [packagePath, path.join(packagePath, 'lib'), path.join(packagePath, 'src')];
    const jsFiles = [];

    for (const dir of scanDirs) {
      if (!fs.existsSync(dir)) continue;
      try {
        const entries = fs.readdirSync(dir);
        for (const entry of entries) {
          if (entry.endsWith('.js') || entry.endsWith('.mjs') || entry.endsWith('.cjs')) {
            jsFiles.push(path.join(dir, entry));
          }
        }
      } catch (e) { /* skip unreadable dirs */ }
    }

    // Limit to first 20 files to keep it fast
    const filesToScan = jsFiles.slice(0, 20);

    for (const file of filesToScan) {
      try {
        const content = fs.readFileSync(file, 'utf8');

        if (/require\(['"]fs['"]\)|from\s+['"]fs['"]|require\(['"]fs\/promises['"]\)/.test(content)) caps.fs = true;
        if (/require\(['"]net['"]\)|from\s+['"]net['"]/.test(content)) caps.net = true;
        if (/require\(['"]http['"]\)|from\s+['"]http['"]/.test(content)) caps.http = true;
        if (/require\(['"]https['"]\)|from\s+['"]https['"]/.test(content)) caps.https = true;
        if (/require\(['"]dns['"]\)|from\s+['"]dns['"]/.test(content)) caps.dns = true;
        if (/require\(['"]child_process['"]\)|from\s+['"]child_process['"]/.test(content)) caps.child_process = true;
        if (/require\(['"]crypto['"]\)|from\s+['"]crypto['"]/.test(content)) caps.crypto = true;
        if (/require\(['"]os['"]\)|from\s+['"]os['"]/.test(content)) caps.os = true;
        if (/process\.env/.test(content)) caps.process_env = true;
      } catch (e) { /* skip unreadable files */ }
    }

    return caps;
  }

  /**
   * Compare current state against last snapshot and report drift
   */
  detectDrift() {
    const snapshotPath = path.join(this.snapshotDir, 'latest.json');
    if (!fs.existsSync(snapshotPath)) {
      throw new Error('No snapshot found. Run `sudarshana snapshot` first.');
    }

    const snapshot = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
    const current = this.snapshot();

    const drifts = [];

    // Check each package
    for (const [pkgName, currentData] of Object.entries(current.packages)) {
      const snapshotData = snapshot.packages[pkgName];

      if (!snapshotData) {
        // New package added
        drifts.push({
          package: pkgName,
          type: 'NEW_PACKAGE',
          severity: 'MEDIUM',
          detail: `New dependency added: ${pkgName}@${currentData.version}`
        });
        continue;
      }

      // Version changed
      if (currentData.version !== snapshotData.version) {
        drifts.push({
          package: pkgName,
          type: 'VERSION_CHANGED',
          severity: 'LOW',
          detail: `${snapshotData.version} → ${currentData.version}`
        });
      }

      // Content hash changed (same version but different content = CRITICAL)
      if (currentData.contentHash && snapshotData.contentHash &&
          currentData.contentHash !== snapshotData.contentHash &&
          currentData.version === snapshotData.version) {
        drifts.push({
          package: pkgName,
          type: 'CONTENT_MODIFIED',
          severity: 'CRITICAL',
          detail: `Same version (${currentData.version}) but content hash changed! Possible tampering.`
        });
      }

      // New capabilities
      if (currentData.capabilities && snapshotData.capabilities) {
        for (const [cap, hasIt] of Object.entries(currentData.capabilities)) {
          if (hasIt && !snapshotData.capabilities[cap]) {
            const severity = ['child_process', 'net', 'dns'].includes(cap) ? 'HIGH' : 'MEDIUM';
            drifts.push({
              package: pkgName,
              type: 'NEW_CAPABILITY',
              severity,
              detail: `Now uses '${cap}' — was not present before`
            });
          }
        }
      }

      // Install scripts added
      if (currentData.hasInstallScripts && !snapshotData.hasInstallScripts) {
        drifts.push({
          package: pkgName,
          type: 'INSTALL_SCRIPT_ADDED',
          severity: 'HIGH',
          detail: `Install script added — check for malicious postinstall`
        });
      }

      // Maintainer changed
      if (currentData.publishedBy && snapshotData.publishedBy &&
          currentData.publishedBy !== snapshotData.publishedBy) {
        drifts.push({
          package: pkgName,
          type: 'MAINTAINER_CHANGED',
          severity: 'HIGH',
          detail: `Published by: ${snapshotData.publishedBy} → ${currentData.publishedBy}`
        });
      }
    }

    // Check for removed packages
    for (const pkgName of Object.keys(snapshot.packages)) {
      if (!current.packages[pkgName]) {
        drifts.push({
          package: pkgName,
          type: 'PACKAGE_REMOVED',
          severity: 'LOW',
          detail: `Dependency removed`
        });
      }
    }

    return {
      snapshotDate: snapshot.timestamp,
      currentDate: current.timestamp,
      totalDrifts: drifts.length,
      critical: drifts.filter(d => d.severity === 'CRITICAL').length,
      high: drifts.filter(d => d.severity === 'HIGH').length,
      medium: drifts.filter(d => d.severity === 'MEDIUM').length,
      low: drifts.filter(d => d.severity === 'LOW').length,
      drifts
    };
  }

  /**
   * Generate human-readable drift report
   */
  generateReport(driftResult) {
    const lines = [];
    lines.push('');
    lines.push('🔍 SUDARSHANA — Drift Detection Report');
    lines.push('═'.repeat(55));
    lines.push(`  Snapshot:  ${driftResult.snapshotDate}`);
    lines.push(`  Current:   ${driftResult.currentDate}`);
    lines.push(`  Changes:   ${driftResult.totalDrifts}`);
    lines.push('');

    if (driftResult.totalDrifts === 0) {
      lines.push('  ✅ No drift detected. All packages match snapshot.');
      lines.push('');
      return lines.join('\n');
    }

    lines.push(`  🔴 CRITICAL: ${driftResult.critical}`);
    lines.push(`  🟠 HIGH:     ${driftResult.high}`);
    lines.push(`  🟡 MEDIUM:   ${driftResult.medium}`);
    lines.push(`  🔵 LOW:      ${driftResult.low}`);
    lines.push('');

    // Group by severity
    const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
    for (const drift of driftResult.drifts) {
      bySeverity[drift.severity].push(drift);
    }

    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      const items = bySeverity[severity];
      if (items.length === 0) continue;

      const icon = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' }[severity];
      lines.push(`  ${icon} ${severity}:`);
      for (const item of items) {
        lines.push(`     ${item.package} — ${item.type}`);
        lines.push(`     └─ ${item.detail}`);
      }
      lines.push('');
    }

    if (driftResult.critical > 0) {
      lines.push('  ⚠️  CRITICAL drifts detected!');
      lines.push('  Same version with different content = possible supply chain attack.');
      lines.push('  Run: npm cache clean --force && rm -rf node_modules && npm install');
      lines.push('');
    }

    return lines.join('\n');
  }
}

module.exports = { DriftDetector };
