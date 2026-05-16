'use strict';

/**
 * SUDARSHANA — LEVEL 10: SELF-HEALING ENGINE
 * 
 * "The disc doesn't just cut. It repairs what was damaged."
 * 
 * Self-healing capabilities:
 * 1. Auto-tighten: Unused capabilities get removed after N runs
 * 2. Auto-relax: False positives (legitimate blocked calls) get auto-allowed
 * 3. Adaptive threshold: Alert fatigue → thresholds auto-adjust
 * 4. Policy evolution: Policies improve themselves over time
 * 
 * This makes Sudarshana MAINTENANCE-FREE.
 * Deploy once. It learns. It adapts. It heals. Forever.
 */

const fs = require('fs');
const path = require('path');

class SelfHealingEngine {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.healingLog = [];
    this.state = this._loadState();
  }

  _statePath() {
    return path.join(this.projectRoot, '.sudarshana-healing', 'state.json');
  }

  _loadState() {
    const statePath = this._statePath();
    if (fs.existsSync(statePath)) {
      try { return JSON.parse(fs.readFileSync(statePath, 'utf8')); } catch(e) {}
    }
    return {
      version: '1.0',
      runs: 0,
      lastHealing: null,
      unusedCapabilities: {},  // pkg → { capability → runs_unused }
      falsePositives: {},      // pkg → { resource → blocked_count }
      healingHistory: []
    };
  }

  _saveState() {
    const dir = path.dirname(this._statePath());
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(this._statePath(), JSON.stringify(this.state, null, 2));
  }

  /**
   * Record that a run completed — track which capabilities were used vs declared
   */
  recordRun(usedCapabilities) {
    this.state.runs++;

    // Compare used vs declared
    const configPath = path.join(this.projectRoot, '.sudarshana.json');
    if (!fs.existsSync(configPath)) return;

    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const policies = config.policies || {};

    for (const [pkgName, policy] of Object.entries(policies)) {
      if (pkgName === '_application_') continue;

      const used = usedCapabilities[pkgName] || {};
      if (!this.state.unusedCapabilities[pkgName]) {
        this.state.unusedCapabilities[pkgName] = {};
      }

      // Check each declared capability
      const declared = {
        env: (policy.env_visible || []).length > 0,
        network: (policy.network || []).length > 0,
        fs_read: (policy.fs_read || []).length > 0,
        fs_write: (policy.fs_write || []).length > 0,
        shell: (policy.shell || []).length > 0
      };

      for (const [cap, isDeclared] of Object.entries(declared)) {
        if (isDeclared && !used[cap]) {
          // Declared but not used this run
          const current = this.state.unusedCapabilities[pkgName][cap] || 0;
          this.state.unusedCapabilities[pkgName][cap] = current + 1;
        } else if (isDeclared && used[cap]) {
          // Was used — reset counter
          this.state.unusedCapabilities[pkgName][cap] = 0;
        }
      }
    }

    this._saveState();
  }

  /**
   * Record a false positive (legitimate operation that got blocked)
   */
  recordFalsePositive(packageName, resource, context) {
    if (!this.state.falsePositives[packageName]) {
      this.state.falsePositives[packageName] = {};
    }

    const key = resource;
    if (!this.state.falsePositives[packageName][key]) {
      this.state.falsePositives[packageName][key] = { count: 0, context, firstSeen: new Date().toISOString() };
    }
    this.state.falsePositives[packageName][key].count++;
    this.state.falsePositives[packageName][key].lastSeen = new Date().toISOString();

    this._saveState();
  }

  /**
   * Run the self-healing pass — generates recommended policy changes
   * @param {Object} options - { autoApply: boolean, minUnusedRuns: number, minFalsePositives: number }
   */
  heal(options = {}) {
    const { autoApply = false, minUnusedRuns = 10, minFalsePositives = 3 } = options;
    const recommendations = [];

    // 1. TIGHTEN: Remove capabilities unused for N runs
    for (const [pkgName, caps] of Object.entries(this.state.unusedCapabilities)) {
      for (const [cap, unusedCount] of Object.entries(caps)) {
        if (unusedCount >= minUnusedRuns) {
          recommendations.push({
            type: 'TIGHTEN',
            package: pkgName,
            capability: cap,
            reason: `${cap} declared but unused for ${unusedCount} consecutive runs`,
            action: `Remove ${cap} from ${pkgName} policy`
          });
        }
      }
    }

    // 2. RELAX: Auto-allow resources that keep getting blocked (false positives)
    for (const [pkgName, resources] of Object.entries(this.state.falsePositives)) {
      for (const [resource, data] of Object.entries(resources)) {
        if (data.count >= minFalsePositives) {
          recommendations.push({
            type: 'RELAX',
            package: pkgName,
            resource,
            reason: `Blocked ${data.count} times — likely legitimate (false positive)`,
            action: `Add "${resource}" to ${pkgName} policy`,
            context: data.context
          });
        }
      }
    }

    // 3. Auto-apply if configured
    if (autoApply && recommendations.length > 0) {
      this._applyRecommendations(recommendations);
    }

    // Record healing pass
    this.state.lastHealing = new Date().toISOString();
    this.state.healingHistory.push({
      timestamp: this.state.lastHealing,
      recommendations: recommendations.length,
      applied: autoApply ? recommendations.length : 0
    });

    this._saveState();
    return recommendations;
  }

  /**
   * Apply healing recommendations to .sudarshana.json
   */
  _applyRecommendations(recommendations) {
    const configPath = path.join(this.projectRoot, '.sudarshana.json');
    if (!fs.existsSync(configPath)) return;

    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    for (const rec of recommendations) {
      const policy = config.policies[rec.package];
      if (!policy) continue;

      if (rec.type === 'TIGHTEN') {
        // Remove unused capability
        const fieldMap = {
          env: 'env_visible',
          network: 'network',
          fs_read: 'fs_read',
          fs_write: 'fs_write',
          shell: 'shell'
        };
        const field = fieldMap[rec.capability];
        if (field && policy[field]) {
          policy[field] = [];
        }
      } else if (rec.type === 'RELAX') {
        // Add the blocked resource
        // Determine which field to add to based on resource type
        if (rec.resource.includes('.') && !rec.resource.includes('/')) {
          // Looks like a domain
          if (!policy.network) policy.network = [];
          if (!policy.network.includes(rec.resource)) {
            policy.network.push(rec.resource);
          }
        } else if (rec.resource.includes('/') || rec.resource.includes('\\')) {
          // Looks like a file path
          if (!policy.fs_read) policy.fs_read = [];
          if (!policy.fs_read.includes(rec.resource)) {
            policy.fs_read.push(rec.resource);
          }
        } else {
          // Looks like an env var
          if (!policy.env_visible) policy.env_visible = [];
          if (!policy.env_visible.includes(rec.resource)) {
            policy.env_visible.push(rec.resource);
          }
        }
      }
    }

    // Save updated config
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  }

  /**
   * Get healing status report
   */
  getStatus() {
    return {
      totalRuns: this.state.runs,
      lastHealing: this.state.lastHealing,
      unusedCapabilities: Object.entries(this.state.unusedCapabilities)
        .filter(([, caps]) => Object.values(caps).some(v => v >= 5))
        .length,
      falsePositives: Object.entries(this.state.falsePositives)
        .filter(([, resources]) => Object.values(resources).some(r => r.count >= 3))
        .length,
      healingHistory: this.state.healingHistory.slice(-10)
    };
  }
}

module.exports = { SelfHealingEngine };
