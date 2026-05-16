'use strict';

/**
 * SUDARSHANA — LEVEL 15: GLOBAL IMMUNE SYSTEM
 * 
 * "Every machine running Sudarshana is a white blood cell.
 *  Attack detected anywhere = blocked everywhere. Instantly."
 * 
 * The immune system operates on three principles:
 * 
 * 1. DETECTION (any node):
 *    - Honeypot triggered → new antibody created
 *    - Behavioral DNA mutation → new antibody created
 *    - Pre-crime score exceeded → preemptive antibody
 * 
 * 2. PROPAGATION (all nodes):
 *    - New antibody → broadcast to P2P network
 *    - All nodes receive and activate antibody within seconds
 *    - Consensus: 3+ nodes confirm = antibody is permanent
 * 
 * 3. IMMUNITY (forever):
 *    - Antibody = {package, version, threat_type, behavioral_signature}
 *    - Any future install attempt of this package@version → auto-blocked
 *    - Even VARIANTS are caught (same behavioral signature, different name)
 * 
 * This creates herd immunity for software:
 * - 1 developer catches malware → 1 million developers are protected
 * - Attacker publishes to npm → blocked within seconds globally
 * - New variant appears → behavioral signature still matches
 * 
 * Like biological immune systems:
 * - First exposure: detect + respond + create antibody
 * - Second exposure: instant recognition + block (zero time)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class ImmuneSystem {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.immuneDir = path.join(this.projectRoot, '.sudarshana-immune');
    this.antibodies = this._loadAntibodies();
    this.stats = { detected: 0, propagated: 0, blocked: 0, variants_caught: 0 };
  }

  _ensureDir() {
    if (!fs.existsSync(this.immuneDir)) fs.mkdirSync(this.immuneDir, { recursive: true });
  }

  _antibodiesPath() { return path.join(this.immuneDir, 'antibodies.json'); }

  _loadAntibodies() {
    this._ensureDir();
    const p = this._antibodiesPath();
    if (fs.existsSync(p)) {
      try { return JSON.parse(fs.readFileSync(p, 'utf8')).antibodies || []; } catch(e) {}
    }
    return [];
  }

  _saveAntibodies() {
    fs.writeFileSync(this._antibodiesPath(), JSON.stringify({
      version: '1.0',
      lastUpdated: new Date().toISOString(),
      count: this.antibodies.length,
      antibodies: this.antibodies
    }, null, 2));
  }

  /**
   * Create a new antibody from a detected threat
   * An antibody contains enough information to recognize this threat
   * AND its variants
   */
  createAntibody(threat) {
    const {
      package: packageName,
      version,
      threatType,
      evidence = {},
      behavioralSignature = null
    } = threat;

    const antibody = {
      id: 'AB-' + crypto.randomBytes(6).toString('hex').toUpperCase(),
      created: new Date().toISOString(),
      source: 'local',
      confidence: 'HIGH',
      confirmations: 1,

      // Exact match criteria
      exact: {
        package: packageName,
        version,
        contentHash: evidence.contentHash || null
      },

      // Behavioral signature (catches variants)
      signature: behavioralSignature || this._generateSignature(threat),

      // Threat metadata
      threat: {
        type: threatType,
        severity: evidence.severity || 'CRITICAL',
        description: `${packageName}@${version}: ${threatType}`
      },

      // Response action
      action: {
        type: threatType === 'HONEYPOT_ACCESS' ? 'QUARANTINE' : 'BLOCK',
        killProcess: false,
        alertLevel: 'CRITICAL'
      }
    };

    this.antibodies.push(antibody);
    this._saveAntibodies();
    this.stats.detected++;

    return antibody;
  }

  /**
   * Generate a behavioral signature from threat evidence
   * This signature can match VARIANTS (same attack, different package name)
   */
  _generateSignature(threat) {
    const evidence = threat.evidence || {};

    return {
      // What the malware DOES (behavior, not identity)
      behaviors: [
        evidence.readsEnv ? 'ENV_READ' : null,
        evidence.makesNetwork ? 'NETWORK_SEND' : null,
        evidence.writesFiles ? 'FS_WRITE' : null,
        evidence.executesShell ? 'SHELL_EXEC' : null,
        evidence.usesDns ? 'DNS_EXFIL' : null,
        evidence.usesEncoding ? 'ENCODING' : null,
        evidence.hasInstallScript ? 'INSTALL_SCRIPT' : null,
      ].filter(Boolean),

      // What it targets (which secrets/paths)
      targets: evidence.targetsEnvVars || [],

      // Network patterns (C2 domain structure)
      networkPattern: evidence.c2Pattern || null,

      // Code fingerprint (structural hash — catches renamed variants)
      codeStructure: evidence.codeStructureHash || null,

      // Timing pattern (when does it activate)
      timing: evidence.timing || null
    };
  }

  /**
   * Check if a package matches any known antibody
   * Checks BOTH exact match AND behavioral signature match
   */
  check(packageName, version, observedBehavior = null) {
    // 1. Exact match (fastest)
    const exactMatch = this.antibodies.find(ab =>
      ab.exact.package === packageName && ab.exact.version === version
    );
    if (exactMatch) {
      this.stats.blocked++;
      return {
        matched: true,
        antibody: exactMatch,
        matchType: 'EXACT',
        action: exactMatch.action
      };
    }

    // 2. Package name match (any version flagged)
    const packageMatch = this.antibodies.find(ab =>
      ab.exact.package === packageName
    );
    if (packageMatch) {
      this.stats.blocked++;
      return {
        matched: true,
        antibody: packageMatch,
        matchType: 'PACKAGE_FLAGGED',
        action: { ...packageMatch.action, note: 'Different version but same package is flagged' }
      };
    }

    // 3. Behavioral signature match (catches variants!)
    if (observedBehavior) {
      const signatureMatch = this._matchSignature(observedBehavior);
      if (signatureMatch) {
        this.stats.variants_caught++;
        return {
          matched: true,
          antibody: signatureMatch,
          matchType: 'BEHAVIORAL_VARIANT',
          action: signatureMatch.action,
          note: `Behavioral match with ${signatureMatch.exact.package} — likely same attacker/variant`
        };
      }
    }

    return { matched: false };
  }

  /**
   * Match observed behavior against known antibody signatures
   */
  _matchSignature(observedBehavior) {
    for (const antibody of this.antibodies) {
      if (!antibody.signature || !antibody.signature.behaviors) continue;

      const sigBehaviors = new Set(antibody.signature.behaviors);
      const obsBehaviors = new Set(observedBehavior.behaviors || []);

      // Calculate overlap
      const overlap = [...sigBehaviors].filter(b => obsBehaviors.has(b));
      const similarity = sigBehaviors.size > 0 ? overlap.length / sigBehaviors.size : 0;

      // 70% behavioral match = variant detected
      if (similarity >= 0.7) {
        // Additional check: target overlap
        const sigTargets = new Set(antibody.signature.targets || []);
        const obsTargets = new Set(observedBehavior.targets || []);
        const targetOverlap = [...sigTargets].filter(t => obsTargets.has(t));

        if (sigTargets.size === 0 || targetOverlap.length > 0) {
          return antibody;
        }
      }
    }

    return null;
  }

  /**
   * Receive antibody from P2P network (external source)
   */
  receiveAntibody(antibody) {
    // Verify it's not a duplicate
    const exists = this.antibodies.find(ab => ab.id === antibody.id);
    if (exists) {
      exists.confirmations = (exists.confirmations || 1) + 1;
      this._saveAntibodies();
      return { action: 'CONFIRMED', confirmations: exists.confirmations };
    }

    // Add with lower initial confidence (external source)
    const imported = {
      ...antibody,
      source: 'network',
      confidence: antibody.confirmations >= 3 ? 'HIGH' : 'MEDIUM',
      receivedAt: new Date().toISOString()
    };

    this.antibodies.push(imported);
    this._saveAntibodies();
    this.stats.propagated++;

    return { action: 'IMPORTED', id: imported.id };
  }

  /**
   * Export antibodies for P2P sharing (privacy-preserving)
   */
  exportAntibodies() {
    return this.antibodies.map(ab => ({
      id: ab.id,
      created: ab.created,
      confirmations: ab.confirmations,
      exact: { package: ab.exact.package, version: ab.exact.version },
      signature: ab.signature,
      threat: ab.threat,
      action: ab.action
      // NOTE: no evidence details, no project info, no user data
    }));
  }

  /**
   * Get immune system status
   */
  getStatus() {
    const highConfidence = this.antibodies.filter(ab => ab.confidence === 'HIGH').length;
    const fromNetwork = this.antibodies.filter(ab => ab.source === 'network').length;

    return {
      totalAntibodies: this.antibodies.length,
      highConfidence,
      fromNetwork,
      local: this.antibodies.length - fromNetwork,
      stats: this.stats,
      lastUpdated: this.antibodies.length > 0
        ? this.antibodies[this.antibodies.length - 1].created
        : null,
      coverage: `${this.antibodies.length} threats recognized instantly`
    };
  }

  /**
   * Generate immune system report
   */
  generateReport() {
    const status = this.getStatus();
    const lines = [];
    lines.push('');
    lines.push('🛡️  SUDARSHANA — Immune System Status');
    lines.push('═'.repeat(55));
    lines.push(`  Antibodies:       ${status.totalAntibodies}`);
    lines.push(`  High confidence:  ${status.highConfidence}`);
    lines.push(`  From network:     ${status.fromNetwork}`);
    lines.push(`  Local detections: ${status.local}`);
    lines.push('');
    lines.push(`  Lifetime stats:`);
    lines.push(`    Threats detected:      ${status.stats.detected}`);
    lines.push(`    Propagated to network: ${status.stats.propagated}`);
    lines.push(`    Auto-blocked:          ${status.stats.blocked}`);
    lines.push(`    Variants caught:       ${status.stats.variants_caught}`);
    lines.push('');

    if (this.antibodies.length > 0) {
      lines.push('  Recent antibodies:');
      for (const ab of this.antibodies.slice(-5)) {
        lines.push(`    ${ab.id} — ${ab.exact.package}@${ab.exact.version} [${ab.confidence}]`);
      }
    } else {
      lines.push('  No antibodies yet. Deploy honeypots to start building immunity.');
    }

    lines.push('');
    return lines.join('\n');
  }
}

module.exports = { ImmuneSystem };
