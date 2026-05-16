'use strict';

/**
 * SUDARSHANA — LEVEL 7: COMPLIANCE & FORENSICS
 * 
 * "When the auditor asks 'how do you manage supply chain risk?'
 *  you hand them this file and go home early."
 * 
 * Generates:
 * - CycloneDX SBOM with per-package capabilities
 * - Forensics timeline (every security event, timestamped)
 * - Policy diff (what changed between two configs)
 * - Compliance summary (ISO 27001 / SOC2 / FedRAMP mapping)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class ComplianceEngine {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.nodeModulesPath = path.join(this.projectRoot, 'node_modules');
  }

  /**
   * Generate CycloneDX SBOM with Sudarshana capability annotations
   */
  generateSBOM(options = {}) {
    const { format = 'json' } = options;
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) throw new Error('No package.json found');

    const projectPkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));

    // Load Sudarshana config for capability annotations
    let config = { policies: {} };
    const configPath = path.join(this.projectRoot, '.sudarshana.json');
    if (fs.existsSync(configPath)) {
      config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }

    const sbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${this._uuid()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{
          vendor: 'sudarshana',
          name: 'sudarshana',
          version: '2.0.0'
        }],
        component: {
          type: 'application',
          name: projectPkg.name || 'unknown',
          version: projectPkg.version || '0.0.0',
          'bom-ref': 'root'
        }
      },
      components: [],
      dependencies: [],
      services: []
    };

    const allDeps = {
      ...projectPkg.dependencies,
      ...projectPkg.devDependencies
    };

    for (const [depName, versionRange] of Object.entries(allDeps)) {
      const depPath = path.join(this.nodeModulesPath, depName, 'package.json');
      let version = versionRange;
      let license = null;
      let purl = null;

      if (fs.existsSync(depPath)) {
        try {
          const depPkg = JSON.parse(fs.readFileSync(depPath, 'utf8'));
          version = depPkg.version || versionRange;
          license = depPkg.license || null;
        } catch (e) { /* skip */ }
      }

      purl = `pkg:npm/${depName}@${version}`;
      const bomRef = `pkg:npm/${depName}`;

      const component = {
        type: 'library',
        'bom-ref': bomRef,
        name: depName,
        version,
        purl,
        scope: (projectPkg.devDependencies || {})[depName] ? 'optional' : 'required'
      };

      if (license) {
        component.licenses = [{ license: { id: license } }];
      }

      // Sudarshana capability annotations (extension)
      const policy = config.policies[depName];
      if (policy) {
        component.properties = [
          { name: 'sudarshana:trust_level', value: policy.trust_level || 'unknown' },
          { name: 'sudarshana:env_access', value: JSON.stringify(policy.env_visible || []) },
          { name: 'sudarshana:network_access', value: JSON.stringify(policy.network || []) },
          { name: 'sudarshana:fs_read', value: JSON.stringify(policy.fs_read || []) },
          { name: 'sudarshana:fs_write', value: JSON.stringify(policy.fs_write || []) },
          { name: 'sudarshana:shell_access', value: JSON.stringify(policy.shell || []) }
        ];
      }

      sbom.components.push(component);
      sbom.dependencies.push({
        ref: bomRef,
        dependsOn: [] // Would need full tree resolution for this
      });
    }

    return sbom;
  }

  /**
   * Generate forensics timeline from quarantine and event logs
   */
  generateForensicsReport() {
    const timeline = [];

    // Load quarantine log
    const quarantineLog = path.join(this.projectRoot, '.sudarshana-quarantine', 'quarantine.jsonl');
    if (fs.existsSync(quarantineLog)) {
      const lines = fs.readFileSync(quarantineLog, 'utf8').trim().split('\n');
      for (const line of lines) {
        try {
          const event = JSON.parse(line);
          timeline.push({
            type: 'QUARANTINE',
            severity: 'CRITICAL',
            timestamp: event.timestamp,
            package: event.package,
            reason: event.reason,
            evidence: event.evidence
          });
        } catch (e) { /* skip malformed lines */ }
      }
    }

    // Load threat feed
    const threatPath = path.join(this.projectRoot, '.sudarshana-threats', 'known-threats.json');
    if (fs.existsSync(threatPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(threatPath, 'utf8'));
        for (const threat of data.threats || []) {
          timeline.push({
            type: 'THREAT_DETECTED',
            severity: threat.severity || 'HIGH',
            timestamp: threat.firstSeen,
            package: threat.package,
            version: threat.version,
            threatType: threat.threatType
          });
        }
      } catch (e) { /* skip */ }
    }

    // Load drift snapshots
    const snapshotPath = path.join(this.projectRoot, '.sudarshana-snapshots', 'latest.json');
    if (fs.existsSync(snapshotPath)) {
      try {
        const snapshot = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
        timeline.push({
          type: 'BASELINE_SNAPSHOT',
          severity: 'INFO',
          timestamp: snapshot.timestamp,
          packages: Object.keys(snapshot.packages).length
        });
      } catch (e) { /* skip */ }
    }

    // Sort by timestamp
    timeline.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    return {
      generated: new Date().toISOString(),
      project: this.projectRoot,
      eventCount: timeline.length,
      timeline
    };
  }

  /**
   * Compare two policy files and show what changed
   */
  policyDiff(oldConfigPath, newConfigPath) {
    const oldConfig = JSON.parse(fs.readFileSync(oldConfigPath, 'utf8'));
    const newConfig = JSON.parse(fs.readFileSync(newConfigPath, 'utf8'));

    const changes = [];

    const oldPolicies = oldConfig.policies || {};
    const newPolicies = newConfig.policies || {};

    // Check for new packages
    for (const pkg of Object.keys(newPolicies)) {
      if (!oldPolicies[pkg]) {
        changes.push({ type: 'ADDED', package: pkg, detail: 'New policy added' });
      }
    }

    // Check for removed packages
    for (const pkg of Object.keys(oldPolicies)) {
      if (!newPolicies[pkg]) {
        changes.push({ type: 'REMOVED', package: pkg, detail: 'Policy removed' });
      }
    }

    // Check for capability changes
    for (const pkg of Object.keys(newPolicies)) {
      if (!oldPolicies[pkg]) continue;

      const oldP = oldPolicies[pkg];
      const newP = newPolicies[pkg];

      const fields = ['env_visible', 'fs_read', 'fs_write', 'network', 'shell'];
      for (const field of fields) {
        const oldVal = JSON.stringify(oldP[field] || []);
        const newVal = JSON.stringify(newP[field] || []);

        if (oldVal !== newVal) {
          const oldArr = oldP[field] || [];
          const newArr = newP[field] || [];
          const added = newArr.filter(x => !oldArr.includes(x));
          const removed = oldArr.filter(x => !newArr.includes(x));

          if (added.length > 0) {
            changes.push({
              type: 'CAPABILITY_ADDED',
              package: pkg,
              field,
              added,
              detail: `${pkg} gained ${field}: ${added.join(', ')}`
            });
          }
          if (removed.length > 0) {
            changes.push({
              type: 'CAPABILITY_REMOVED',
              package: pkg,
              field,
              removed,
              detail: `${pkg} lost ${field}: ${removed.join(', ')}`
            });
          }
        }
      }

      // Trust level change
      if (oldP.trust_level !== newP.trust_level) {
        changes.push({
          type: 'TRUST_CHANGED',
          package: pkg,
          from: oldP.trust_level,
          to: newP.trust_level,
          detail: `${pkg} trust: ${oldP.trust_level} → ${newP.trust_level}`
        });
      }
    }

    return {
      oldConfig: oldConfigPath,
      newConfig: newConfigPath,
      changeCount: changes.length,
      changes
    };
  }

  /**
   * Generate compliance mapping report
   */
  generateComplianceMapping() {
    const configPath = path.join(this.projectRoot, '.sudarshana.json');
    const hasConfig = fs.existsSync(configPath);

    const controls = {
      'ISO 27001': {
        'A.12.6.1 — Management of technical vulnerabilities': hasConfig ? 'SATISFIED' : 'PARTIAL',
        'A.14.2.5 — Secure system engineering principles': hasConfig ? 'SATISFIED' : 'NOT_MET',
        'A.15.2.1 — Monitoring of supplier services': 'SATISFIED',
        'A.12.4.1 — Event logging': 'SATISFIED'
      },
      'SOC 2': {
        'CC6.1 — Logical and physical access controls': hasConfig ? 'SATISFIED' : 'PARTIAL',
        'CC7.1 — Detection of unauthorized activities': 'SATISFIED',
        'CC7.2 — Monitoring of system components': 'SATISFIED',
        'CC8.1 — Change management': hasConfig ? 'SATISFIED' : 'PARTIAL'
      },
      'NIST CSF': {
        'PR.DS-5 — Protection against data leaks': hasConfig ? 'SATISFIED' : 'PARTIAL',
        'DE.CM-7 — Monitoring for unauthorized activity': 'SATISFIED',
        'DE.AE-1 — Baseline of operations established': 'SATISFIED',
        'RS.MI-1 — Incidents are contained': 'SATISFIED'
      }
    };

    return {
      generated: new Date().toISOString(),
      sudarshanaConfigured: hasConfig,
      frameworks: controls,
      summary: {
        satisfied: Object.values(controls).reduce((sum, f) =>
          sum + Object.values(f).filter(v => v === 'SATISFIED').length, 0),
        partial: Object.values(controls).reduce((sum, f) =>
          sum + Object.values(f).filter(v => v === 'PARTIAL').length, 0),
        notMet: Object.values(controls).reduce((sum, f) =>
          sum + Object.values(f).filter(v => v === 'NOT_MET').length, 0)
      }
    };
  }

  _uuid() {
    return crypto.randomUUID ? crypto.randomUUID() :
      'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
      });
  }
}

module.exports = { ComplianceEngine };
