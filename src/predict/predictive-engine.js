'use strict';

/**
 * SUDARSHANA — LEVEL 8: PREDICTIVE ENGINE
 * 
 * "Don't wait for the attack. See it coming."
 * 
 * Features:
 * 1. Anomaly Detection — statistical baseline, flag deviations
 * 2. Transitive Risk — "your safe package depends on a dangerous one"
 * 3. Maintainer Trust Chain — detect ownership changes
 * 4. Pre-Merge Simulation — predict what a new package will do
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class PredictiveEngine {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.nodeModulesPath = path.join(this.projectRoot, 'node_modules');
  }

  // ═══════════════════════════════════════════════════════════
  // ANOMALY DETECTION
  // Statistical baseline → flag outliers WITHOUT rules
  // ═══════════════════════════════════════════════════════════

  /**
   * Build a behavioral baseline from current observations
   * Returns: per-package average activity levels
   */
  buildBaseline(learnData) {
    const baselines = {};

    for (const [pkgName, data] of Object.entries(learnData)) {
      const envCount = Object.keys(data.env || {}).length;
      const fsReadCount = Object.keys(data.fs_read || {}).length;
      const fsWriteCount = Object.keys(data.fs_write || {}).length;
      const netCount = Object.keys(data.network || {}).length;
      const dnsCount = Object.keys(data.dns || {}).length;
      const shellCount = Object.keys(data.shell || {}).length;

      baselines[pkgName] = {
        env: envCount,
        fs_read: fsReadCount,
        fs_write: fsWriteCount,
        network: netCount,
        dns: dnsCount,
        shell: shellCount,
        totalActivity: envCount + fsReadCount + fsWriteCount + netCount + dnsCount + shellCount
      };
    }

    return baselines;
  }

  /**
   * Detect anomalies by comparing current behavior against baseline
   * Uses Z-score: if activity is > 2 standard deviations from mean → anomaly
   */
  detectAnomalies(baseline, currentActivity) {
    const anomalies = [];

    // Calculate global mean and stddev for each category
    const categories = ['env', 'fs_read', 'fs_write', 'network', 'dns', 'shell'];
    const stats = {};

    for (const cat of categories) {
      const values = Object.values(baseline).map(b => b[cat] || 0);
      const mean = values.reduce((a, b) => a + b, 0) / (values.length || 1);
      const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / (values.length || 1);
      const stddev = Math.sqrt(variance);
      stats[cat] = { mean, stddev };
    }

    // Check each package's current activity
    for (const [pkgName, current] of Object.entries(currentActivity)) {
      const base = baseline[pkgName];

      for (const cat of categories) {
        const currentVal = current[cat] || 0;
        const baselineVal = base ? (base[cat] || 0) : 0;
        const { mean, stddev } = stats[cat];

        // Z-score: how many standard deviations from mean?
        const zScore = stddev > 0 ? (currentVal - mean) / stddev : 0;

        // Flag if:
        // 1. Z-score > 2 (statistical outlier)
        // 2. OR value went from 0 to non-zero (new capability)
        if (zScore > 2 || (baselineVal === 0 && currentVal > 0)) {
          const severity = (baselineVal === 0 && currentVal > 0) ? 'HIGH' :
                          zScore > 3 ? 'HIGH' : 'MEDIUM';

          anomalies.push({
            package: pkgName,
            category: cat,
            severity,
            baselineValue: baselineVal,
            currentValue: currentVal,
            zScore: Math.round(zScore * 100) / 100,
            description: baselineVal === 0
              ? `${pkgName} now uses ${cat} (never seen before)`
              : `${pkgName} ${cat} activity is ${zScore.toFixed(1)}σ above normal`
          });
        }
      }
    }

    return anomalies.sort((a, b) => b.zScore - a.zScore);
  }

  // ═══════════════════════════════════════════════════════════
  // TRANSITIVE RISK ANALYSIS
  // "Your safe package depends on a dangerous one"
  // ═══════════════════════════════════════════════════════════

  /**
   * Calculate transitive risk — propagate risk through dependency tree
   */
  calculateTransitiveRisk(directRiskScores) {
    const transitiveRisk = {};

    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return {};

    const projectPkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const allDeps = Object.keys({
      ...projectPkg.dependencies,
      ...projectPkg.devDependencies
    });

    for (const dep of allDeps) {
      const depPath = path.join(this.nodeModulesPath, dep, 'package.json');
      if (!fs.existsSync(depPath)) continue;

      try {
        const depPkg = JSON.parse(fs.readFileSync(depPath, 'utf8'));
        const transitiveDeps = Object.keys(depPkg.dependencies || {});

        let maxTransitiveRisk = 0;
        let riskiestDep = null;
        const riskyChain = [];

        for (const td of transitiveDeps) {
          const tdRisk = directRiskScores[td] || 0;
          if (tdRisk > maxTransitiveRisk) {
            maxTransitiveRisk = tdRisk;
            riskiestDep = td;
          }
          if (tdRisk > 25) {
            riskyChain.push({ package: td, risk: tdRisk });
          }
        }

        // Transitive risk = own risk + 50% of worst dependency risk
        const ownRisk = directRiskScores[dep] || 0;
        const combinedRisk = Math.min(100, ownRisk + Math.floor(maxTransitiveRisk * 0.5));

        transitiveRisk[dep] = {
          ownRisk,
          maxTransitiveRisk,
          combinedRisk,
          riskiestDependency: riskiestDep,
          riskyChain,
          transitiveDepsCount: transitiveDeps.length
        };
      } catch (e) { /* skip */ }
    }

    return transitiveRisk;
  }

  // ═══════════════════════════════════════════════════════════
  // MAINTAINER TRUST CHAIN
  // Detect ownership changes on packages
  // ═══════════════════════════════════════════════════════════

  /**
   * Analyze maintainer information for red flags
   */
  analyzeMaintainerTrust() {
    const results = {};
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return {};

    const projectPkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const allDeps = Object.keys({
      ...projectPkg.dependencies,
      ...projectPkg.devDependencies
    });

    for (const dep of allDeps) {
      const depPath = path.join(this.nodeModulesPath, dep, 'package.json');
      if (!fs.existsSync(depPath)) continue;

      try {
        const depPkg = JSON.parse(fs.readFileSync(depPath, 'utf8'));
        const maintainers = depPkg.maintainers || [];
        const npmUser = depPkg._npmUser;

        const flags = [];

        // Flag: single maintainer (bus factor)
        if (maintainers.length === 1) {
          flags.push({ type: 'SINGLE_MAINTAINER', severity: 'LOW', detail: 'Bus factor = 1' });
        }

        // Flag: _npmUser different from maintainers list
        if (npmUser && maintainers.length > 0) {
          const maintainerNames = maintainers.map(m => m.name || m.email || m);
          const publisherName = npmUser.name || npmUser.email || npmUser;
          if (!maintainerNames.includes(publisherName)) {
            flags.push({
              type: 'PUBLISHER_NOT_IN_MAINTAINERS',
              severity: 'HIGH',
              detail: `Published by "${publisherName}" but maintainers are: ${maintainerNames.join(', ')}`
            });
          }
        }

        // Flag: no repository
        if (!depPkg.repository) {
          flags.push({ type: 'NO_REPOSITORY', severity: 'LOW', detail: 'No source repository linked' });
        }

        // Flag: repository moved to different org
        if (depPkg.repository) {
          const repoUrl = typeof depPkg.repository === 'string' ? depPkg.repository : depPkg.repository.url || '';
          if (repoUrl.includes('github.com')) {
            // Could check if org in URL matches expected — needs baseline
          }
        }

        results[dep] = {
          version: depPkg.version,
          maintainers: maintainers.map(m => m.name || m.email || m),
          publisher: npmUser ? (npmUser.name || npmUser.email) : null,
          flags,
          trustScore: 100 - (flags.filter(f => f.severity === 'HIGH').length * 30) -
                           (flags.filter(f => f.severity === 'MEDIUM').length * 15) -
                           (flags.filter(f => f.severity === 'LOW').length * 5)
        };
      } catch (e) { /* skip */ }
    }

    return results;
  }

  // ═══════════════════════════════════════════════════════════
  // PRE-MERGE SIMULATION
  // "What would this package do if I installed it?"
  // ═══════════════════════════════════════════════════════════

  /**
   * Simulate what a package WOULD do before installing
   * Analyzes its package.json + source from node_modules (if installed)
   * or predicts from name + known patterns
   */
  simulatePackage(packageName) {
    const depPath = path.join(this.nodeModulesPath, packageName);
    const predictions = {
      package: packageName,
      predictions: [],
      riskAssessment: 'UNKNOWN',
      recommendation: 'REVIEW'
    };

    if (!fs.existsSync(depPath)) {
      predictions.predictions.push({
        type: 'NOT_INSTALLED',
        detail: 'Package not in node_modules — install to analyze'
      });
      return predictions;
    }

    const pkgJsonPath = path.join(depPath, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return predictions;

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));

    // Predict based on dependencies
    const deps = Object.keys(pkg.dependencies || {});
    const networkDeps = ['axios', 'node-fetch', 'got', 'request', 'undici', 'http-proxy'];
    const fsDeps = ['fs-extra', 'graceful-fs', 'glob', 'chokidar', 'rimraf'];
    const shellDeps = ['execa', 'cross-spawn', 'shelljs'];

    const hasNetDeps = deps.some(d => networkDeps.includes(d));
    const hasFsDeps = deps.some(d => fsDeps.includes(d));
    const hasShellDeps = deps.some(d => shellDeps.includes(d));

    if (hasNetDeps) {
      predictions.predictions.push({
        type: 'WILL_USE_NETWORK',
        confidence: 'HIGH',
        detail: `Depends on: ${deps.filter(d => networkDeps.includes(d)).join(', ')}`
      });
    }

    if (hasFsDeps) {
      predictions.predictions.push({
        type: 'WILL_USE_FILESYSTEM',
        confidence: 'HIGH',
        detail: `Depends on: ${deps.filter(d => fsDeps.includes(d)).join(', ')}`
      });
    }

    if (hasShellDeps) {
      predictions.predictions.push({
        type: 'WILL_EXECUTE_SHELL',
        confidence: 'HIGH',
        detail: `Depends on: ${deps.filter(d => shellDeps.includes(d)).join(', ')}`
      });
    }

    // Check install scripts
    if (pkg.scripts) {
      if (pkg.scripts.postinstall) {
        predictions.predictions.push({
          type: 'HAS_POSTINSTALL',
          confidence: 'CERTAIN',
          detail: `postinstall: "${pkg.scripts.postinstall}"`,
          risk: 'ELEVATED'
        });
      }
      if (pkg.scripts.preinstall) {
        predictions.predictions.push({
          type: 'HAS_PREINSTALL',
          confidence: 'CERTAIN',
          detail: `preinstall: "${pkg.scripts.preinstall}"`,
          risk: 'HIGH'
        });
      }
    }

    // Check if native
    if (pkg.gypfile) {
      predictions.predictions.push({
        type: 'NATIVE_ADDON',
        confidence: 'CERTAIN',
        detail: 'Uses node-gyp (C/C++ compilation)',
        risk: 'ELEVATED'
      });
    }

    // Assess overall risk
    const highRiskCount = predictions.predictions.filter(p =>
      p.risk === 'HIGH' || p.type === 'WILL_EXECUTE_SHELL'
    ).length;
    const elevatedCount = predictions.predictions.filter(p =>
      p.risk === 'ELEVATED' || p.type === 'WILL_USE_NETWORK'
    ).length;

    if (highRiskCount > 0) {
      predictions.riskAssessment = 'HIGH';
      predictions.recommendation = 'RESTRICT — Apply strict policy before using';
    } else if (elevatedCount > 0) {
      predictions.riskAssessment = 'MODERATE';
      predictions.recommendation = 'CONFIGURE — Declare allowed domains/paths';
    } else if (predictions.predictions.length === 0) {
      predictions.riskAssessment = 'LOW';
      predictions.recommendation = 'SAFE — Appears to be pure compute';
    } else {
      predictions.riskAssessment = 'MODERATE';
      predictions.recommendation = 'REVIEW — Check specific capabilities';
    }

    // Suggest policy
    predictions.suggestedPolicy = {
      trust_level: highRiskCount > 0 ? 'untrusted' : elevatedCount > 0 ? 'limited' : 'trusted',
      env_visible: [],
      fs_read: hasFsDeps ? ['./*'] : [],
      fs_write: [],
      network: hasNetDeps ? ['CONFIGURE_DOMAINS'] : [],
      shell: hasShellDeps ? ['REVIEW_COMMANDS'] : []
    };

    return predictions;
  }

  /**
   * Generate predictive risk report
   */
  generateReport(transitiveRisk, anomalies, maintainerTrust) {
    const lines = [];
    lines.push('');
    lines.push('🧠 SUDARSHANA — Predictive Risk Assessment');
    lines.push('═'.repeat(55));
    lines.push('');

    // Transitive risk
    if (Object.keys(transitiveRisk).length > 0) {
      lines.push('📊 TRANSITIVE RISK (hidden dependencies):');
      lines.push('');
      const risky = Object.entries(transitiveRisk)
        .filter(([, r]) => r.combinedRisk > r.ownRisk + 10)
        .sort(([, a], [, b]) => b.combinedRisk - a.combinedRisk)
        .slice(0, 10);

      for (const [name, data] of risky) {
        lines.push(`  ⚠️  ${name.padEnd(25)} own:${String(data.ownRisk).padStart(3)} → combined:${String(data.combinedRisk).padStart(3)}`);
        if (data.riskiestDependency) {
          lines.push(`     └─ via: ${data.riskiestDependency} (risk: ${data.maxTransitiveRisk})`);
        }
      }
      if (risky.length === 0) lines.push('  ✅ No significant transitive risk elevation');
      lines.push('');
    }

    // Anomalies
    if (anomalies && anomalies.length > 0) {
      lines.push('🚨 ANOMALIES DETECTED:');
      lines.push('');
      for (const a of anomalies.slice(0, 10)) {
        const icon = a.severity === 'HIGH' ? '🔴' : '🟡';
        lines.push(`  ${icon} ${a.description}`);
      }
      lines.push('');
    }

    // Maintainer trust
    if (Object.keys(maintainerTrust).length > 0) {
      const flagged = Object.entries(maintainerTrust)
        .filter(([, m]) => m.flags.length > 0 && m.flags.some(f => f.severity === 'HIGH'))
        .slice(0, 5);

      if (flagged.length > 0) {
        lines.push('👤 MAINTAINER FLAGS:');
        lines.push('');
        for (const [name, data] of flagged) {
          for (const flag of data.flags.filter(f => f.severity === 'HIGH')) {
            lines.push(`  🟠 ${name}: ${flag.detail}`);
          }
        }
        lines.push('');
      }
    }

    return lines.join('\n');
  }
}

module.exports = { PredictiveEngine };
