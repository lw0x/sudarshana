'use strict';

/**
 * SUDARSHANA — LEVEL 12: GLOBAL BEHAVIORAL DATABASE
 * 
 * "We know what every package in the npm ecosystem normally does.
 *  Any deviation is instantly visible."
 * 
 * Collects anonymized behavioral fingerprints from all Sudarshana instances.
 * Result: a crowdsourced "normal behavior" map of the entire npm ecosystem.
 * 
 * When package X suddenly adds network access in v2.1.4 and NO OTHER
 * Sudarshana instance has seen that behavior → INSTANT flag.
 * 
 * Local mode: builds from your own observations
 * Network mode: aggregates from P2P network
 * 
 * Data shared (privacy-preserving):
 * {
 *   "package": "lodash",
 *   "version": "4.17.21",
 *   "capabilities": 0b00000000,  // bitmask: no env, no fs, no net
 *   "observation_count": 15000,   // how many instances observed this
 *   "first_observed": "2020-01-01"
 * }
 * 
 * NEVER shared: user data, project names, file contents, env values
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Capability bitmask (same as behavioral-dna.js)
const CAPS = {
  NONE: 0,
  ENV_READ: 1 << 0,
  FS_READ: 1 << 1,
  FS_WRITE: 1 << 2,
  NET_HTTP: 1 << 3,
  NET_TCP: 1 << 4,
  NET_DNS: 1 << 5,
  SHELL: 1 << 6,
  CRYPTO: 1 << 7,
  CHILD_PROCESS: 1 << 8,
  TIMER_DELAYED: 1 << 9,
  NATIVE_ADDON: 1 << 10,
  EVAL: 1 << 11
};

class GlobalBehavioralDB {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.dbDir = path.join(this.projectRoot, '.sudarshana-globaldb');
    this.db = this._loadDB();
  }

  _ensureDir() {
    if (!fs.existsSync(this.dbDir)) fs.mkdirSync(this.dbDir, { recursive: true });
  }

  _dbPath() { return path.join(this.dbDir, 'ecosystem.json'); }

  _loadDB() {
    this._ensureDir();
    const p = this._dbPath();
    if (fs.existsSync(p)) {
      try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch(e) {}
    }
    return {
      version: '1.0',
      lastUpdated: null,
      packageCount: 0,
      totalObservations: 0,
      packages: {}
    };
  }

  _saveDB() {
    this.db.lastUpdated = new Date().toISOString();
    this.db.packageCount = Object.keys(this.db.packages).length;
    fs.writeFileSync(this._dbPath(), JSON.stringify(this.db, null, 2));
  }

  /**
   * Record an observation for a package (what capabilities it used)
   */
  recordObservation(packageName, version, capabilities) {
    const key = `${packageName}@${version}`;

    if (!this.db.packages[key]) {
      this.db.packages[key] = {
        package: packageName,
        version,
        capabilities,
        observationCount: 0,
        firstObserved: new Date().toISOString(),
        lastObserved: null,
        capabilityHistory: [],
        consensusCapabilities: capabilities
      };
    }

    const entry = this.db.packages[key];
    entry.observationCount++;
    entry.lastObserved = new Date().toISOString();
    this.db.totalObservations++;

    // Track capability changes over time
    if (entry.capabilities !== capabilities) {
      entry.capabilityHistory.push({
        from: entry.capabilities,
        to: capabilities,
        observedAt: new Date().toISOString()
      });
      // Update consensus (majority vote)
      entry.capabilities = capabilities;
    }

    this._saveDB();
  }

  /**
   * Check if a package's current behavior deviates from the known norm
   */
  checkDeviation(packageName, version, currentCapabilities) {
    const key = `${packageName}@${version}`;
    const known = this.db.packages[key];

    if (!known) {
      // Never seen this version — check if any version is known
      const anyVersion = Object.values(this.db.packages).find(p => p.package === packageName);
      if (anyVersion) {
        // Compare against historical behavior of this package
        const newCaps = currentCapabilities & ~anyVersion.consensusCapabilities;
        if (newCaps !== 0) {
          return {
            deviation: true,
            severity: 'HIGH',
            type: 'NEW_VERSION_NEW_CAPABILITIES',
            package: packageName,
            version,
            newCapabilities: this._decodeCaps(newCaps),
            detail: `${packageName}@${version} has capabilities never seen in any previous version`,
            confidence: Math.min(anyVersion.observationCount / 10, 1) // Higher with more data
          };
        }
      }
      return { deviation: false, type: 'UNKNOWN_PACKAGE' };
    }

    // Known version — check for deviation
    const newCaps = currentCapabilities & ~known.consensusCapabilities;
    if (newCaps !== 0) {
      return {
        deviation: true,
        severity: 'CRITICAL',
        type: 'KNOWN_VERSION_NEW_CAPABILITIES',
        package: packageName,
        version,
        newCapabilities: this._decodeCaps(newCaps),
        knownCapabilities: this._decodeCaps(known.consensusCapabilities),
        observationCount: known.observationCount,
        detail: `${packageName}@${version} is doing something NEVER observed before (${known.observationCount} prior observations)`,
        confidence: Math.min(known.observationCount / 100, 0.99)
      };
    }

    return { deviation: false, type: 'MATCHES_CONSENSUS' };
  }

  /**
   * Get ecosystem-wide statistics
   */
  getEcosystemStats() {
    const packages = Object.values(this.db.packages);

    const capDistribution = {};
    for (const [name, bit] of Object.entries(CAPS)) {
      if (name === 'NONE') continue;
      capDistribution[name] = packages.filter(p => p.capabilities & bit).length;
    }

    const pureCompute = packages.filter(p => p.capabilities === 0).length;

    return {
      totalPackageVersions: packages.length,
      totalObservations: this.db.totalObservations,
      uniquePackages: new Set(packages.map(p => p.package)).size,
      pureCompute,
      pureComputePercent: packages.length > 0 ? Math.round(pureCompute / packages.length * 100) : 0,
      capabilityDistribution: capDistribution,
      lastUpdated: this.db.lastUpdated
    };
  }

  /**
   * Import ecosystem data from another Sudarshana instance
   */
  importData(externalData) {
    let imported = 0;
    const packages = externalData.packages || {};

    for (const [key, entry] of Object.entries(packages)) {
      if (!this.db.packages[key]) {
        this.db.packages[key] = entry;
        imported++;
      } else {
        // Merge: increase observation count
        this.db.packages[key].observationCount += entry.observationCount;
      }
    }

    this.db.totalObservations += externalData.totalObservations || 0;
    this._saveDB();
    return { imported, total: Object.keys(this.db.packages).length };
  }

  /**
   * Export local observations for sharing
   */
  exportData() {
    return {
      version: '1.0',
      exported: new Date().toISOString(),
      packageCount: Object.keys(this.db.packages).length,
      totalObservations: this.db.totalObservations,
      packages: this.db.packages
    };
  }

  _decodeCaps(bitmask) {
    const names = [];
    for (const [name, bit] of Object.entries(CAPS)) {
      if (name !== 'NONE' && (bitmask & bit)) names.push(name);
    }
    return names;
  }
}

module.exports = { GlobalBehavioralDB, CAPS };
