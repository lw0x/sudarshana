'use strict';

/**
 * SUDARSHANA — FREE TIER: LICENSE COMPLIANCE
 * 
 * "What paid license scanners charge $30K/year for. Free."
 * 
 * Scans all dependencies and reports:
 * 1. License of each package (MIT, Apache-2.0, GPL, etc.)
 * 2. License compatibility (is GPL in your MIT project? Problem.)
 * 3. Copyleft detection (GPL/AGPL = must open-source YOUR code)
 * 4. Missing licenses (red flag for enterprise)
 * 5. License change detection (was MIT, now GPL = supply chain attack vector)
 * 
 * Enterprise compliance requirements:
 * - SOC 2: know your dependencies' licenses
 * - EU Cyber Resilience Act: full SBOM with license data
 * - Corporate policy: "no GPL in our SaaS"
 * 
 * Usage:
 *   sudarshana license                 Full license audit
 *   sudarshana license --policy=strict Block GPL/AGPL
 *   sudarshana license --export=csv    Export for legal team
 */

const fs = require('fs');
const path = require('path');

// License categories
const LICENSE_CATEGORIES = {
  PERMISSIVE: ['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', 'Unlicense', 'CC0-1.0', '0BSD', 'Zlib'],
  WEAK_COPYLEFT: ['LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EPL-1.0', 'EPL-2.0', 'CDDL-1.0'],
  STRONG_COPYLEFT: ['GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'GPL-2.0-only', 'GPL-3.0-only', 'AGPL-3.0-only'],
  NON_COMMERCIAL: ['CC-BY-NC-4.0', 'CC-BY-NC-SA-4.0', 'Commons-Clause'],
  UNKNOWN: ['UNKNOWN', 'SEE LICENSE IN', 'UNLICENSED'],
};

// Default policies
const POLICIES = {
  permissive: {
    name: 'Permissive Only',
    allow: ['PERMISSIVE'],
    warn: ['WEAK_COPYLEFT'],
    block: ['STRONG_COPYLEFT', 'NON_COMMERCIAL', 'UNKNOWN'],
  },
  moderate: {
    name: 'Moderate (allow weak copyleft)',
    allow: ['PERMISSIVE', 'WEAK_COPYLEFT'],
    warn: ['UNKNOWN'],
    block: ['STRONG_COPYLEFT', 'NON_COMMERCIAL'],
  },
  strict: {
    name: 'Strict Enterprise',
    allow: ['PERMISSIVE'],
    warn: [],
    block: ['WEAK_COPYLEFT', 'STRONG_COPYLEFT', 'NON_COMMERCIAL', 'UNKNOWN'],
  }
};

class LicenseCompliance {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.nodeModulesPath = path.join(this.projectRoot, 'node_modules');
  }

  /**
   * Scan all dependencies for license information
   */
  scan() {
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) throw new Error('No package.json found');

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    const results = [];

    for (const dep of deps) {
      const depPkgPath = path.join(this.nodeModulesPath, dep, 'package.json');
      if (!fs.existsSync(depPkgPath)) continue;

      try {
        const depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf8'));
        const license = this._extractLicense(depPkg);
        const category = this._categorize(license);

        results.push({
          package: dep,
          version: depPkg.version,
          license,
          category,
          repository: typeof depPkg.repository === 'string' ? depPkg.repository :
                     (depPkg.repository ? depPkg.repository.url : null),
          author: depPkg.author ? (typeof depPkg.author === 'string' ? depPkg.author : depPkg.author.name) : null
        });
      } catch(e) {
        results.push({ package: dep, license: 'ERROR', category: 'UNKNOWN', error: e.message });
      }
    }

    return results;
  }

  /**
   * Apply a license policy and report violations
   */
  enforce(scanResults, policyName = 'moderate') {
    const policy = POLICIES[policyName] || POLICIES.moderate;
    const violations = { blocked: [], warned: [], allowed: [] };

    for (const pkg of scanResults) {
      const status = this._checkPolicy(pkg.category, policy);
      if (status === 'BLOCK') {
        violations.blocked.push({ ...pkg, status: 'BLOCKED', reason: `${pkg.license} is ${pkg.category} — not allowed by "${policy.name}" policy` });
      } else if (status === 'WARN') {
        violations.warned.push({ ...pkg, status: 'WARNING', reason: `${pkg.license} (${pkg.category}) — review required` });
      } else {
        violations.allowed.push(pkg);
      }
    }

    return {
      policy: policy.name,
      total: scanResults.length,
      blocked: violations.blocked.length,
      warned: violations.warned.length,
      allowed: violations.allowed.length,
      violations
    };
  }

  /**
   * Detect license changes (supply chain indicator)
   * If a package was MIT and is now GPL → red flag
   */
  detectLicenseChanges(currentScan, previousScan) {
    const changes = [];

    for (const current of currentScan) {
      const previous = previousScan.find(p => p.package === current.package);
      if (previous && previous.license !== current.license) {
        const wasPermissive = this._categorize(previous.license) === 'PERMISSIVE';
        const nowCopyleft = ['STRONG_COPYLEFT', 'WEAK_COPYLEFT'].includes(this._categorize(current.license));

        changes.push({
          package: current.package,
          from: previous.license,
          to: current.license,
          severity: (wasPermissive && nowCopyleft) ? 'CRITICAL' : 'MEDIUM',
          detail: wasPermissive && nowCopyleft
            ? `⚠️ License changed from permissive (${previous.license}) to copyleft (${current.license})! May require open-sourcing your code.`
            : `License changed: ${previous.license} → ${current.license}`
        });
      }
    }

    return changes;
  }

  /**
   * Export license data for legal team
   */
  exportCSV(scanResults) {
    const header = 'Package,Version,License,Category,Repository,Author';
    const rows = scanResults.map(r =>
      `"${r.package}","${r.version || ''}","${r.license}","${r.category}","${r.repository || ''}","${r.author || ''}"`
    );
    return [header, ...rows].join('\n');
  }

  /**
   * Generate compliance report
   */
  generateReport(enforcement) {
    const lines = [];
    lines.push('');
    lines.push('📜 SUDARSHANA — License Compliance Report');
    lines.push('═'.repeat(55));
    lines.push(`  Policy:    ${enforcement.policy}`);
    lines.push(`  Scanned:   ${enforcement.total} packages`);
    lines.push(`  Allowed:   ${enforcement.allowed} ✅`);
    lines.push(`  Warnings:  ${enforcement.warned} ⚠️`);
    lines.push(`  Blocked:   ${enforcement.blocked} 🔴`);
    lines.push('');

    if (enforcement.violations.blocked.length > 0) {
      lines.push('  🔴 BLOCKED (policy violation):');
      for (const v of enforcement.violations.blocked) {
        lines.push(`    ${v.package}@${v.version} — ${v.license} (${v.category})`);
        lines.push(`      → ${v.reason}`);
      }
      lines.push('');
    }

    if (enforcement.violations.warned.length > 0) {
      lines.push('  ⚠️  WARNINGS (review required):');
      for (const v of enforcement.violations.warned) {
        lines.push(`    ${v.package}@${v.version} — ${v.license}`);
      }
      lines.push('');
    }

    // License distribution
    const dist = {};
    for (const pkg of [...enforcement.violations.allowed, ...enforcement.violations.warned, ...enforcement.violations.blocked]) {
      dist[pkg.license] = (dist[pkg.license] || 0) + 1;
    }
    lines.push('  📊 License Distribution:');
    const sorted = Object.entries(dist).sort((a, b) => b[1] - a[1]);
    for (const [license, count] of sorted.slice(0, 10)) {
      const bar = '█'.repeat(Math.min(20, Math.round(count / enforcement.total * 40)));
      lines.push(`    ${license.padEnd(15)} ${bar} ${count}`);
    }
    lines.push('');

    return lines.join('\n');
  }

  // ═══ Helpers ═══

  _extractLicense(pkg) {
    if (pkg.license) {
      if (typeof pkg.license === 'string') return pkg.license;
      if (pkg.license.type) return pkg.license.type;
    }
    if (pkg.licenses) {
      if (Array.isArray(pkg.licenses)) return pkg.licenses.map(l => l.type || l).join(' OR ');
    }
    // Check for LICENSE file
    return 'UNKNOWN';
  }

  _categorize(license) {
    if (!license) return 'UNKNOWN';
    const upper = license.toUpperCase();

    for (const [category, licenses] of Object.entries(LICENSE_CATEGORIES)) {
      if (licenses.some(l => upper.includes(l.toUpperCase()))) return category;
    }

    // Common patterns
    if (upper.includes('MIT') || upper.includes('ISC')) return 'PERMISSIVE';
    if (upper.includes('GPL') || upper.includes('AGPL')) return 'STRONG_COPYLEFT';
    if (upper.includes('LGPL') || upper.includes('MPL')) return 'WEAK_COPYLEFT';
    if (upper.includes('APACHE')) return 'PERMISSIVE';
    if (upper.includes('BSD')) return 'PERMISSIVE';

    return 'UNKNOWN';
  }

  _checkPolicy(category, policy) {
    if (policy.block.includes(category)) return 'BLOCK';
    if (policy.warn.includes(category)) return 'WARN';
    return 'ALLOW';
  }
}

module.exports = { LicenseCompliance, LICENSE_CATEGORIES, POLICIES };
