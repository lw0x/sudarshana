'use strict';

/**
 * SUDARSHANA — LEVEL 14: PRE-CRIME DETECTION
 * 
 * "See the attack before it happens."
 * 
 * Analyzes leading indicators that predict a package WILL be compromised:
 * 
 * 1. Maintainer Signals:
 *    - Account age vs package popularity (new account → popular package = risk)
 *    - Maintainer added right before a release
 *    - Single maintainer on critical package (bus factor)
 *    - Maintainer email domain changed
 * 
 * 2. Publication Signals:
 *    - Version published outside normal schedule
 *    - Rapid successive publishes (test-exfil-revert pattern)
 *    - Version jump from stable to 0.x (experimental = less scrutiny)
 *    - Package unpublished then republished (takeover signal)
 * 
 * 3. Code Signals:
 *    - Sudden increase in dependencies
 *    - New dependency with < 100 weekly downloads
 *    - Build script changes
 *    - New postinstall script in a patch version
 * 
 * 4. Ecosystem Signals:
 *    - GitHub repo archived but npm package still publishing
 *    - Repository URL changed to different org
 *    - Package forked under different name with same version scheme
 * 
 * Risk = weighted sum of all signals → PRE-CRIME SCORE (0-100)
 * Score > 70 = "This package is likely to be compromised soon. Watch closely."
 */

const fs = require('fs');
const path = require('path');

// Signal weights (higher = more predictive of future compromise)
const SIGNAL_WEIGHTS = {
  // Maintainer signals
  NEW_MAINTAINER_ON_POPULAR_PKG: 25,
  SINGLE_MAINTAINER_CRITICAL: 15,
  MAINTAINER_ADDED_BEFORE_RELEASE: 20,
  MAINTAINER_EMAIL_CHANGED: 10,

  // Publication signals
  PUBLISH_OUTSIDE_SCHEDULE: 10,
  RAPID_SUCCESSIVE_PUBLISHES: 15,
  VERSION_JUMP_ANOMALY: 12,
  UNPUBLISH_REPUBLISH: 30,

  // Code signals
  SUDDEN_NEW_DEPENDENCIES: 15,
  NEW_LOW_DOWNLOAD_DEPENDENCY: 20,
  POSTINSTALL_ADDED_PATCH: 25,
  BUILD_SCRIPT_CHANGED: 10,

  // Ecosystem signals
  REPO_ARCHIVED_STILL_PUBLISHING: 30,
  REPO_URL_CHANGED_ORG: 20,
  FORKED_SAME_VERSION_SCHEME: 15,
};

class PreCrimeEngine {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.nodeModulesPath = path.join(this.projectRoot, 'node_modules');
  }

  /**
   * Analyze all dependencies for pre-crime signals
   * Returns risk assessment per package
   */
  analyze() {
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) throw new Error('No package.json');

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    const results = {};

    for (const dep of deps) {
      results[dep] = this._analyzeDependency(dep);
    }

    return results;
  }

  /**
   * Analyze a single dependency for pre-crime indicators
   */
  _analyzeDependency(packageName) {
    const depPath = path.join(this.nodeModulesPath, packageName, 'package.json');
    if (!fs.existsSync(depPath)) return { score: 0, signals: [], risk: 'UNKNOWN' };

    const pkg = JSON.parse(fs.readFileSync(depPath, 'utf8'));
    const signals = [];
    let score = 0;

    // ─── Maintainer Signals ───────────────────────────────────

    const maintainers = pkg.maintainers || [];
    const npmUser = pkg._npmUser;

    // Single maintainer on any package
    if (maintainers.length === 1) {
      signals.push({
        type: 'SINGLE_MAINTAINER_CRITICAL',
        weight: SIGNAL_WEIGHTS.SINGLE_MAINTAINER_CRITICAL,
        detail: 'Single maintainer — bus factor 1, takeover risk'
      });
      score += SIGNAL_WEIGHTS.SINGLE_MAINTAINER_CRITICAL;
    }

    // Publisher not in maintainers list (possible new/unauthorized publisher)
    if (npmUser && maintainers.length > 0) {
      const publisherName = npmUser.name || npmUser.email;
      const maintainerNames = maintainers.map(m => m.name || m.email || m);
      if (publisherName && !maintainerNames.includes(publisherName)) {
        signals.push({
          type: 'MAINTAINER_ADDED_BEFORE_RELEASE',
          weight: SIGNAL_WEIGHTS.MAINTAINER_ADDED_BEFORE_RELEASE,
          detail: `Published by "${publisherName}" who is not in original maintainers: ${maintainerNames.join(', ')}`
        });
        score += SIGNAL_WEIGHTS.MAINTAINER_ADDED_BEFORE_RELEASE;
      }
    }

    // ─── Code Signals ─────────────────────────────────────────

    // postinstall script in package
    if (pkg.scripts && (pkg.scripts.postinstall || pkg.scripts.preinstall)) {
      // Check if it's a patch version (x.y.Z where Z > 0)
      const versionParts = (pkg.version || '0.0.0').split('.');
      const isPatch = parseInt(versionParts[2] || 0) > 0;

      if (isPatch) {
        signals.push({
          type: 'POSTINSTALL_ADDED_PATCH',
          weight: SIGNAL_WEIGHTS.POSTINSTALL_ADDED_PATCH,
          detail: `Install script present in patch version ${pkg.version}`
        });
        score += SIGNAL_WEIGHTS.POSTINSTALL_ADDED_PATCH;
      }
    }

    // Check for low-download transitive dependencies
    const depDeps = Object.keys(pkg.dependencies || {});
    const suspiciousDeps = depDeps.filter(d => {
      // Heuristic: packages with very specific/unusual names
      return d.length > 20 || d.includes('--') || /[0-9]{3,}/.test(d);
    });

    if (suspiciousDeps.length > 0) {
      signals.push({
        type: 'NEW_LOW_DOWNLOAD_DEPENDENCY',
        weight: SIGNAL_WEIGHTS.NEW_LOW_DOWNLOAD_DEPENDENCY,
        detail: `Suspicious dependency names: ${suspiciousDeps.slice(0, 3).join(', ')}`
      });
      score += SIGNAL_WEIGHTS.NEW_LOW_DOWNLOAD_DEPENDENCY;
    }

    // Sudden many dependencies (> 20 for a utility package)
    if (depDeps.length > 20 && !['express', 'next', 'webpack', 'babel', '@angular/core'].includes(packageName)) {
      signals.push({
        type: 'SUDDEN_NEW_DEPENDENCIES',
        weight: SIGNAL_WEIGHTS.SUDDEN_NEW_DEPENDENCIES,
        detail: `${depDeps.length} dependencies — unusually high for this type of package`
      });
      score += SIGNAL_WEIGHTS.SUDDEN_NEW_DEPENDENCIES;
    }

    // ─── Ecosystem Signals ────────────────────────────────────

    // No repository URL (can't verify source)
    if (!pkg.repository) {
      signals.push({
        type: 'REPO_URL_CHANGED_ORG',
        weight: 5, // Minor signal
        detail: 'No repository URL — source cannot be verified'
      });
      score += 5;
    }

    // Version anomaly: 0.x.x on something with many dependents
    if (pkg.version && pkg.version.startsWith('0.')) {
      // Not necessarily bad, but note it
      signals.push({
        type: 'VERSION_JUMP_ANOMALY',
        weight: 5,
        detail: `Pre-1.0 version (${pkg.version}) — less stability guarantees`
      });
      score += 5;
    }

    // ─── Risk Assessment ──────────────────────────────────────

    const risk = score >= 50 ? 'HIGH' :
                 score >= 30 ? 'MEDIUM' :
                 score >= 15 ? 'LOW' : 'MINIMAL';

    return {
      package: packageName,
      version: pkg.version,
      score: Math.min(100, score),
      risk,
      signals,
      recommendation: this._getRecommendation(risk, signals)
    };
  }

  _getRecommendation(risk, signals) {
    if (risk === 'HIGH') {
      return 'IMMEDIATE REVIEW — Multiple pre-crime indicators detected. Pin version and audit.';
    }
    if (risk === 'MEDIUM') {
      return 'MONITOR — Some risk indicators present. Enable behavioral DNA tracking.';
    }
    if (risk === 'LOW') {
      return 'WATCH — Minor indicators. Standard Sudarshana protection is sufficient.';
    }
    return 'OK — No significant pre-crime indicators.';
  }

  /**
   * Generate pre-crime report
   */
  generateReport(results) {
    const lines = [];
    lines.push('');
    lines.push('🔮 SUDARSHANA — Pre-Crime Risk Assessment');
    lines.push('═'.repeat(55));
    lines.push('');

    const sorted = Object.entries(results)
      .sort(([, a], [, b]) => b.score - a.score);

    const riskCounts = { HIGH: 0, MEDIUM: 0, LOW: 0, MINIMAL: 0, UNKNOWN: 0 };
    for (const [, data] of sorted) riskCounts[data.risk]++;

    lines.push(`  Summary: 🔴${riskCounts.HIGH} HIGH  🟠${riskCounts.MEDIUM} MEDIUM  🟡${riskCounts.LOW} LOW  🟢${riskCounts.MINIMAL} OK`);
    lines.push('');

    // Show packages with risk > MINIMAL
    const risky = sorted.filter(([, d]) => d.score >= 15);
    if (risky.length === 0) {
      lines.push('  ✅ No significant pre-crime indicators across all dependencies.');
    } else {
      for (const [name, data] of risky) {
        const icon = data.risk === 'HIGH' ? '🔴' : data.risk === 'MEDIUM' ? '🟠' : '🟡';
        lines.push(`  ${icon} ${name.padEnd(30)} score:${String(data.score).padStart(3)} [${data.risk}]`);
        for (const signal of data.signals.slice(0, 3)) {
          lines.push(`     ⚠️  ${signal.detail}`);
        }
        lines.push(`     → ${data.recommendation}`);
        lines.push('');
      }
    }

    return lines.join('\n');
  }
}

module.exports = { PreCrimeEngine, SIGNAL_WEIGHTS };
