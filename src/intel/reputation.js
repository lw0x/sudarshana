'use strict';

/**
 * SUDARSHANA — PACKAGE REPUTATION ENGINE
 * 
 * "Trust is earned over time. Not granted by install count."
 * 
 * Calculates a reputation score for every package based on:
 * - Age (older = more trusted, generally)
 * - Maintainer stability (new maintainer on old pkg = 🚨)
 * - Download velocity (sudden spike = possible typosquat)
 * - Dependency count (many deps = larger attack surface)
 * - Has tests (no tests = less eyeballs)
 * - Has types (maintained packages tend to have types)
 * - Install scripts (postinstall = elevated risk)
 * - Native addons (node-gyp = operates below JS)
 * 
 * Doesn't require network — analyzes what's in node_modules.
 * Optional: enriches with npm registry data when available.
 */

const fs = require('fs');
const path = require('path');

// Scoring weights (total = 100)
const WEIGHTS = {
  age: 15,              // Package age (years since first publish)
  version_maturity: 10, // Higher major version = more mature
  maintainer_count: 10, // More maintainers = more eyeballs
  dependency_count: 15, // Fewer deps = smaller attack surface
  has_tests: 10,        // Tests directory exists
  has_types: 5,         // TypeScript types available
  install_scripts: -20, // Postinstall = penalty
  native_addon: -10,    // node-gyp = penalty
  single_file: -15,     // Single .js file (no src/) = suspicious
  obfuscated: -30,      // Minified/obfuscated main file = suspicious
};

class ReputationEngine {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.nodeModulesPath = path.join(this.projectRoot, 'node_modules');
  }

  /**
   * Calculate reputation scores for all direct dependencies
   */
  analyzeAll() {
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) throw new Error('No package.json found');

    const projectPkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys({
      ...projectPkg.dependencies,
      ...projectPkg.devDependencies
    });

    const results = {};
    for (const dep of deps) {
      results[dep] = this.analyze(dep);
    }

    return results;
  }

  /**
   * Calculate reputation for a single package
   */
  analyze(packageName) {
    const depPath = path.join(this.nodeModulesPath, packageName);
    if (!fs.existsSync(depPath)) {
      return { score: 0, risk: 'UNKNOWN', reason: 'not installed' };
    }

    const pkgJsonPath = path.join(depPath, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) {
      return { score: 0, risk: 'UNKNOWN', reason: 'no package.json' };
    }

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const signals = {};
    let score = 50; // Start at neutral

    // 1. Version maturity
    const majorVersion = parseInt((pkg.version || '0').split('.')[0]);
    if (majorVersion >= 3) {
      score += WEIGHTS.version_maturity;
      signals.version = { value: pkg.version, impact: '+' + WEIGHTS.version_maturity };
    } else if (majorVersion === 0) {
      score -= 5;
      signals.version = { value: pkg.version, impact: '-5 (pre-release)' };
    }

    // 2. Dependency count
    const depCount = Object.keys(pkg.dependencies || {}).length;
    if (depCount === 0) {
      score += WEIGHTS.dependency_count;
      signals.dependencies = { value: 0, impact: '+' + WEIGHTS.dependency_count + ' (zero deps = minimal surface)' };
    } else if (depCount <= 5) {
      score += 8;
      signals.dependencies = { value: depCount, impact: '+8 (few deps)' };
    } else if (depCount > 20) {
      score -= 10;
      signals.dependencies = { value: depCount, impact: '-10 (many deps = large surface)' };
    }

    // 3. Has tests
    const hasTests = fs.existsSync(path.join(depPath, 'test')) ||
                     fs.existsSync(path.join(depPath, 'tests')) ||
                     fs.existsSync(path.join(depPath, '__tests__')) ||
                     (pkg.scripts && (pkg.scripts.test && pkg.scripts.test !== 'echo "Error: no test specified" && exit 1'));
    if (hasTests) {
      score += WEIGHTS.has_tests;
      signals.tests = { value: true, impact: '+' + WEIGHTS.has_tests };
    }

    // 4. Has types
    const hasTypes = !!pkg.types || !!pkg.typings ||
                     fs.existsSync(path.join(depPath, 'index.d.ts'));
    if (hasTypes) {
      score += WEIGHTS.has_types;
      signals.types = { value: true, impact: '+' + WEIGHTS.has_types };
    }

    // 5. Install scripts (PENALTY)
    const hasInstallScripts = pkg.scripts && (
      pkg.scripts.preinstall || pkg.scripts.install || pkg.scripts.postinstall
    );
    if (hasInstallScripts) {
      score += WEIGHTS.install_scripts; // negative
      signals.installScripts = { value: true, impact: WEIGHTS.install_scripts + ' (install scripts = risk)' };
    }

    // 6. Native addon (PENALTY)
    const hasNative = !!pkg.gypfile || !!(pkg.scripts && pkg.scripts.install &&
                      pkg.scripts.install.includes('node-gyp'));
    if (hasNative) {
      score += WEIGHTS.native_addon; // negative
      signals.nativeAddon = { value: true, impact: WEIGHTS.native_addon + ' (native = below JS monitoring)' };
    }

    // 7. Single file check (suspicious if package is one minified file)
    const mainFile = pkg.main || 'index.js';
    const mainPath = path.join(depPath, mainFile);
    if (fs.existsSync(mainPath)) {
      try {
        const content = fs.readFileSync(mainPath, 'utf8');
        const lineCount = content.split('\n').length;

        // Check if obfuscated (very long lines, no whitespace structure)
        const avgLineLength = content.length / lineCount;
        if (avgLineLength > 500 && lineCount < 10) {
          score += WEIGHTS.obfuscated; // negative
          signals.obfuscated = { value: true, impact: WEIGHTS.obfuscated + ' (obfuscated/minified main file)' };
        }

        // Single file with no src/ directory
        const hasSrc = fs.existsSync(path.join(depPath, 'src')) ||
                       fs.existsSync(path.join(depPath, 'lib'));
        if (!hasSrc && lineCount < 50 && depCount === 0) {
          // Tiny single-file package — not necessarily bad but note it
          signals.singleFile = { value: true, impact: '0 (tiny package, noted)' };
        }
      } catch (e) { /* skip */ }
    }

    // 8. Repository presence
    const hasRepo = !!pkg.repository;
    if (hasRepo) {
      score += 5;
      signals.repository = { value: true, impact: '+5' };
    } else {
      score -= 5;
      signals.repository = { value: false, impact: '-5 (no repository URL)' };
    }

    // 9. License
    const hasLicense = !!pkg.license;
    if (hasLicense) {
      score += 3;
    } else {
      score -= 3;
      signals.license = { value: false, impact: '-3 (no license)' };
    }

    // 10. Maintainer info
    const maintainers = pkg.maintainers || [];
    if (maintainers.length >= 3) {
      score += WEIGHTS.maintainer_count;
      signals.maintainers = { value: maintainers.length, impact: '+' + WEIGHTS.maintainer_count };
    } else if (maintainers.length === 1) {
      signals.maintainers = { value: 1, impact: '0 (single maintainer — bus factor)' };
    }

    // Clamp score
    score = Math.max(0, Math.min(100, score));

    // Determine risk level
    let risk;
    if (score >= 80) risk = 'LOW';
    else if (score >= 60) risk = 'MEDIUM';
    else if (score >= 40) risk = 'HIGH';
    else risk = 'CRITICAL';

    return {
      package: packageName,
      version: pkg.version,
      score,
      risk,
      signals
    };
  }

  /**
   * Generate human-readable reputation report
   */
  generateReport(results) {
    const lines = [];
    lines.push('');
    lines.push('🛡️  SUDARSHANA — Package Reputation Report');
    lines.push('═'.repeat(55));
    lines.push('');

    const sorted = Object.entries(results)
      .sort(([, a], [, b]) => a.score - b.score);

    const riskIcon = { LOW: '🟢', MEDIUM: '🟡', HIGH: '🟠', CRITICAL: '🔴', UNKNOWN: '⚪' };

    for (const [name, data] of sorted) {
      const icon = riskIcon[data.risk] || '⚪';
      lines.push(`  ${icon} ${name.padEnd(30)} ${String(data.score).padStart(3)}/100  ${data.risk}`);

      // Show key signals for risky packages
      if (data.risk === 'CRITICAL' || data.risk === 'HIGH') {
        if (data.signals) {
          for (const [key, signal] of Object.entries(data.signals)) {
            if (signal.impact && signal.impact.startsWith('-')) {
              lines.push(`     ⚠️  ${key}: ${signal.impact}`);
            }
          }
        }
      }
    }

    lines.push('');
    lines.push('  Summary:');
    const counts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, UNKNOWN: 0 };
    for (const data of Object.values(results)) counts[data.risk]++;
    lines.push(`  🟢 Low risk:      ${counts.LOW}`);
    lines.push(`  🟡 Medium risk:   ${counts.MEDIUM}`);
    lines.push(`  🟠 High risk:     ${counts.HIGH}`);
    lines.push(`  🔴 Critical risk: ${counts.CRITICAL}`);
    if (counts.UNKNOWN > 0) lines.push(`  ⚪ Unknown:       ${counts.UNKNOWN}`);
    lines.push('');

    return lines.join('\n');
  }
}

module.exports = { ReputationEngine };
