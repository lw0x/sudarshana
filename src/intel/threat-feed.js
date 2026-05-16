'use strict';

/**
 * SUDARSHANA — THREAT INTELLIGENCE FEED
 * 
 * "One Sudarshana catches a threat. ALL Sudarshanas learn instantly."
 * 
 * Anonymous, privacy-preserving threat sharing:
 * - When a package triggers a honeypot → its name + version is flagged
 * - When a package is quarantined → other instances pre-quarantine it
 * - No source code, no credentials, no identifying info is ever shared
 * 
 * Feed format (what gets shared):
 * {
 *   "package": "evil-pkg",
 *   "version": "1.2.3",
 *   "threat_type": "HONEYPOT_ACCESS",
 *   "timestamp": "2025-01-01T00:00:00Z",
 *   "hash": "sha256-of-package-tarball"
 * }
 * 
 * That's it. No user data. No project data. Just "this package is bad."
 * 
 * Local mode: reads/writes from .sudarshana-threats/
 * Network mode (future): anonymized P2P threat sharing
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class ThreatFeed {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.threatDir = path.join(this.projectRoot, '.sudarshana-threats');
    this.threats = new Map(); // packageName@version → threat data
    this._ensureDir();
    this._loadLocal();
  }

  _ensureDir() {
    if (!fs.existsSync(this.threatDir)) {
      fs.mkdirSync(this.threatDir, { recursive: true });
    }
  }

  _localPath() {
    return path.join(this.threatDir, 'known-threats.json');
  }

  _loadLocal() {
    const localPath = this._localPath();
    if (fs.existsSync(localPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(localPath, 'utf8'));
        for (const threat of data.threats || []) {
          this.threats.set(`${threat.package}@${threat.version}`, threat);
        }
      } catch (e) { /* corrupted file, start fresh */ }
    }
  }

  _saveLocal() {
    const data = {
      version: '1.0',
      lastUpdated: new Date().toISOString(),
      threatCount: this.threats.size,
      threats: [...this.threats.values()]
    };
    fs.writeFileSync(this._localPath(), JSON.stringify(data, null, 2));
  }

  /**
   * Report a threat (local + future: broadcast)
   */
  report(packageName, version, threatType, evidence = {}) {
    const key = `${packageName}@${version}`;
    
    if (this.threats.has(key)) {
      // Update existing threat with new evidence
      const existing = this.threats.get(key);
      existing.sightings = (existing.sightings || 1) + 1;
      existing.lastSeen = new Date().toISOString();
      existing.threatTypes = [...new Set([...(existing.threatTypes || [existing.threatType]), threatType])];
    } else {
      this.threats.set(key, {
        package: packageName,
        version,
        threatType,
        threatTypes: [threatType],
        sightings: 1,
        firstSeen: new Date().toISOString(),
        lastSeen: new Date().toISOString(),
        hash: evidence.hash || null,
        severity: this._calculateSeverity(threatType)
      });
    }

    this._saveLocal();
  }

  /**
   * Check if a package+version is known-bad
   */
  isKnownThreat(packageName, version) {
    const key = `${packageName}@${version}`;
    return this.threats.has(key) ? this.threats.get(key) : null;
  }

  /**
   * Check if ANY version of a package is known-bad
   */
  isPackageFlagged(packageName) {
    for (const [key, threat] of this.threats) {
      if (threat.package === packageName) return threat;
    }
    return null;
  }

  /**
   * Get all known threats for pre-scanning
   */
  getAllThreats() {
    return [...this.threats.values()];
  }

  /**
   * Check installed packages against known threats
   */
  scanInstalled() {
    const nodeModulesPath = path.join(this.projectRoot, 'node_modules');
    if (!fs.existsSync(nodeModulesPath)) return [];

    const alerts = [];

    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return [];

    const projectPkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys({
      ...projectPkg.dependencies,
      ...projectPkg.devDependencies
    });

    for (const dep of deps) {
      const depPkgPath = path.join(nodeModulesPath, dep, 'package.json');
      if (!fs.existsSync(depPkgPath)) continue;

      try {
        const depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf8'));
        const version = depPkg.version;

        // Check exact version
        const exactThreat = this.isKnownThreat(dep, version);
        if (exactThreat) {
          alerts.push({
            package: dep,
            version,
            threat: exactThreat,
            match: 'exact'
          });
          continue;
        }

        // Check any version flagged
        const anyThreat = this.isPackageFlagged(dep);
        if (anyThreat) {
          alerts.push({
            package: dep,
            version,
            threat: anyThreat,
            match: 'package_flagged'
          });
        }
      } catch (e) { /* skip */ }
    }

    return alerts;
  }

  /**
   * Import threats from an external feed (JSON)
   */
  importFeed(feedData) {
    let imported = 0;
    const threats = feedData.threats || feedData;

    for (const threat of threats) {
      if (threat.package && threat.version && threat.threatType) {
        const key = `${threat.package}@${threat.version}`;
        if (!this.threats.has(key)) {
          this.threats.set(key, {
            ...threat,
            importedAt: new Date().toISOString()
          });
          imported++;
        }
      }
    }

    this._saveLocal();
    return { imported, total: this.threats.size };
  }

  /**
   * Export local threats for sharing
   */
  exportFeed() {
    return {
      version: '1.0',
      source: 'sudarshana-local',
      exported: new Date().toISOString(),
      threats: [...this.threats.values()].map(t => ({
        package: t.package,
        version: t.version,
        threatType: t.threatType,
        severity: t.severity,
        firstSeen: t.firstSeen,
        hash: t.hash
      }))
    };
  }

  _calculateSeverity(threatType) {
    const severities = {
      'HONEYPOT_ACCESS': 'CRITICAL',
      'SENSITIVE_DATA_EXFILTRATION': 'CRITICAL',
      'CONTENT_MODIFIED': 'CRITICAL',
      'SHELL_EXECUTION': 'HIGH',
      'NEW_CAPABILITY': 'MEDIUM',
      'INSTALL_SCRIPT_ADDED': 'MEDIUM',
      'SUSPICIOUS_NETWORK': 'HIGH'
    };
    return severities[threatType] || 'MEDIUM';
  }
}

module.exports = { ThreatFeed };
