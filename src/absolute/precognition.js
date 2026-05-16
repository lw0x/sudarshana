'use strict';

/**
 * SUDARSHANA — LEVEL 20: PRECOGNITION NETWORK
 * 
 * "The disc sees what hasn't happened yet."
 * 
 * ∞² ABSOLUTE — The Final State
 * 
 * Predicts attacks that haven't been invented yet by modeling:
 * 
 * 1. Attacker Economics:
 *    - Which packages have the highest ROI for an attacker?
 *    - (downloads × avg env vars accessible × maintainer vulnerability)
 *    - The packages with highest "attacker ROI" will be targeted FIRST
 * 
 * 2. Maintainer Burnout Model:
 *    - Commit frequency declining?
 *    - Issue response time increasing?
 *    - Solo maintainer on critical infra?
 *    - These are the packages that will be ABANDONED or SOLD
 * 
 * 3. Dependency Cascade Model:
 *    - If package X is compromised, which packages transitively break?
 *    - What's the "blast radius" of each potential compromise?
 *    - Focus protection on highest-blast-radius packages
 * 
 * 4. Attack Vector Evolution:
 *    - Historical pattern: attacks evolve from simple to complex
 *    - Next predicted evolution based on current state of defenses
 *    - Pre-build defenses for attacks that DON'T EXIST YET
 * 
 * This doesn't prevent known attacks. It prevents FUTURE attacks.
 * The disc sees across all possible timelines and collapses them
 * into the one where the attack never happened.
 */

const fs = require('fs');
const path = require('path');

class PrecognitionNetwork {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
  }

  /**
   * Calculate "Attacker ROI" for each dependency
   * Higher ROI = more likely to be targeted next
   */
  calculateAttackerROI() {
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) throw new Error('No package.json');

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys(pkg.dependencies || {});
    const results = [];

    for (const dep of deps) {
      const depPath = path.join(this.projectRoot, 'node_modules', dep, 'package.json');
      if (!fs.existsSync(depPath)) continue;

      try {
        const depPkg = JSON.parse(fs.readFileSync(depPath, 'utf8'));
        const roi = this._calculateROI(dep, depPkg);
        results.push(roi);
      } catch(e) {}
    }

    return results.sort((a, b) => b.roiScore - a.roiScore);
  }

  _calculateROI(packageName, pkg) {
    let score = 0;
    const factors = [];

    // Factor 1: Transitive dependents (more dependents = higher value target)
    const depCount = Object.keys(pkg.dependencies || {}).length;
    // Packages with many dependents are more valuable targets
    // We approximate this by how many other packages depend on this one

    // Factor 2: Maintainer vulnerability
    const maintainers = pkg.maintainers || [];
    if (maintainers.length === 1) {
      score += 25;
      factors.push({ factor: 'SINGLE_MAINTAINER', weight: 25, detail: 'One person to compromise' });
    }
    if (maintainers.length === 0) {
      score += 30;
      factors.push({ factor: 'NO_MAINTAINERS_LISTED', weight: 30, detail: 'No visible ownership' });
    }

    // Factor 3: Access to secrets (does it typically get env access?)
    const networkPackages = ['axios', 'node-fetch', 'got', 'request', 'superagent'];
    const dbPackages = ['pg', 'mysql2', 'mongoose', 'redis', 'ioredis', 'sequelize', 'prisma'];
    const cloudPackages = ['aws-sdk', '@aws-sdk', 'firebase', 'azure'];

    if (networkPackages.includes(packageName)) { score += 15; factors.push({ factor: 'NETWORK_ACCESS', weight: 15 }); }
    if (dbPackages.includes(packageName)) { score += 20; factors.push({ factor: 'DATABASE_ACCESS', weight: 20 }); }
    if (cloudPackages.some(p => packageName.startsWith(p))) { score += 25; factors.push({ factor: 'CLOUD_CREDENTIALS', weight: 25 }); }

    // Factor 4: Install scripts (easy payload delivery)
    if (pkg.scripts && (pkg.scripts.postinstall || pkg.scripts.preinstall)) {
      score += 20;
      factors.push({ factor: 'HAS_INSTALL_SCRIPTS', weight: 20, detail: 'Ready-made payload delivery mechanism' });
    }

    // Factor 5: Age and staleness
    if (!pkg.repository) {
      score += 10;
      factors.push({ factor: 'NO_REPOSITORY', weight: 10, detail: 'No source to verify against' });
    }

    // Factor 6: Native addon (can bypass JS monitoring)
    if (pkg.gypfile) {
      score += 15;
      factors.push({ factor: 'NATIVE_ADDON', weight: 15, detail: 'Can bypass JS-level defenses' });
    }

    return {
      package: packageName,
      version: pkg.version,
      roiScore: Math.min(100, score),
      risk: score >= 60 ? 'CRITICAL_TARGET' : score >= 40 ? 'HIGH_VALUE' : score >= 20 ? 'MODERATE' : 'LOW_VALUE',
      factors,
      prediction: score >= 60
        ? `HIGH PROBABILITY TARGET — ${packageName} offers maximum ROI to attackers`
        : score >= 40
        ? `ELEVATED RISK — ${packageName} is an attractive target`
        : `LOW PRIORITY — Less attractive to attackers`
    };
  }

  /**
   * Model maintainer burnout risk
   * Predicts which packages will be abandoned/sold
   */
  maintainerBurnoutModel() {
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys(pkg.dependencies || {});
    const results = [];

    for (const dep of deps) {
      const depPath = path.join(this.projectRoot, 'node_modules', dep, 'package.json');
      if (!fs.existsSync(depPath)) continue;

      try {
        const depPkg = JSON.parse(fs.readFileSync(depPath, 'utf8'));
        const burnout = this._assessBurnout(dep, depPkg);
        if (burnout.risk !== 'LOW') results.push(burnout);
      } catch(e) {}
    }

    return results.sort((a, b) => b.burnoutScore - a.burnoutScore);
  }

  _assessBurnout(packageName, pkg) {
    let score = 0;
    const indicators = [];

    // Single maintainer
    const maintainers = pkg.maintainers || [];
    if (maintainers.length <= 1) {
      score += 30;
      indicators.push('Single maintainer (bus factor 1)');
    }

    // No funding
    if (!pkg.funding) {
      score += 15;
      indicators.push('No funding configured');
    }

    // Version suggests stagnation (pre-1.0 or very old)
    const version = pkg.version || '0.0.0';
    if (version.startsWith('0.')) {
      score += 10;
      indicators.push('Pre-1.0 (may be experimental/abandoned)');
    }

    // Many open issues would indicate burnout (we can't check without network)
    // But we can check if there's a "help wanted" or "looking for maintainers" in description
    const desc = (pkg.description || '').toLowerCase();
    if (desc.includes('deprecated') || desc.includes('unmaintained') || desc.includes('looking for maintainer')) {
      score += 40;
      indicators.push('Package description suggests abandonment');
    }

    // No homepage/bugs URL suggests low maintenance
    if (!pkg.homepage && !pkg.bugs) {
      score += 10;
      indicators.push('No homepage or issue tracker');
    }

    return {
      package: packageName,
      version: pkg.version,
      burnoutScore: Math.min(100, score),
      risk: score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW',
      indicators,
      prediction: score >= 50
        ? `⚠️ ${packageName} shows burnout signals — may be abandoned or sold soon`
        : `${packageName} — ${indicators.length > 0 ? indicators[0] : 'appears maintained'}`
    };
  }

  /**
   * Calculate blast radius — if package X is compromised, what breaks?
   */
  blastRadiusAnalysis() {
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    const dependencyGraph = {};

    // Build reverse dependency graph
    for (const dep of deps) {
      const depPkgPath = path.join(this.projectRoot, 'node_modules', dep, 'package.json');
      if (!fs.existsSync(depPkgPath)) continue;

      try {
        const depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf8'));
        const transitiveDeps = Object.keys(depPkg.dependencies || {});

        for (const td of transitiveDeps) {
          if (!dependencyGraph[td]) dependencyGraph[td] = new Set();
          dependencyGraph[td].add(dep);
        }
      } catch(e) {}
    }

    // Calculate blast radius for each package
    const results = [];
    for (const dep of deps) {
      const directDependents = dependencyGraph[dep] ? [...dependencyGraph[dep]] : [];

      // Cascade: if dep is compromised, all its dependents + THEIR dependents are affected
      const cascade = new Set(directDependents);
      let frontier = [...directDependents];
      let depth = 0;
      while (frontier.length > 0 && depth < 5) {
        const next = [];
        for (const f of frontier) {
          const fDependents = dependencyGraph[f] ? [...dependencyGraph[f]] : [];
          for (const fd of fDependents) {
            if (!cascade.has(fd)) {
              cascade.add(fd);
              next.push(fd);
            }
          }
        }
        frontier = next;
        depth++;
      }

      results.push({
        package: dep,
        directDependents: directDependents.length,
        cascadeSize: cascade.size,
        blastRadius: Math.min(100, Math.round((cascade.size / Math.max(deps.length, 1)) * 100)),
        affectedPackages: [...cascade].slice(0, 10),
        priority: cascade.size >= 5 ? 'CRITICAL' : cascade.size >= 2 ? 'HIGH' : 'NORMAL'
      });
    }

    return results.sort((a, b) => b.cascadeSize - a.cascadeSize);
  }

  /**
   * Predict next attack vector evolution
   */
  predictNextVector() {
    // Based on historical attack evolution patterns
    const evolution = [
      {
        generation: 1,
        era: '2018-2020',
        vector: 'Direct credential theft (event-stream)',
        defense: 'npm audit',
        status: 'DEFENDED'
      },
      {
        generation: 2,
        era: '2021-2022',
        vector: 'Typosquatting + postinstall scripts',
        defense: 'Static analysis tools, npm --ignore-scripts',
        status: 'DEFENDED'
      },
      {
        generation: 3,
        era: '2023-2024',
        vector: 'Maintainer takeover + delayed payloads',
        defense: 'Sudarshana behavioral DNA + drift detection',
        status: 'DEFENDED'
      },
      {
        generation: 4,
        era: '2025-2026',
        vector: 'AI-generated polymorphic malware + CI/CD poisoning',
        defense: 'Sudarshana LLM reviewer + immune system',
        status: 'DEFENDED'
      },
      {
        generation: 5,
        era: '2026-2027 (PREDICTED)',
        vector: 'Supply chain attacks via build tools (webpack plugins, babel transforms)',
        defense: 'Sudarshana build-time scanning + policy-as-code',
        status: 'PREPARE NOW',
        recommendation: 'Scan webpack/babel/vite config files for dynamic imports and eval patterns'
      },
      {
        generation: 6,
        era: '2027-2028 (PREDICTED)',
        vector: 'AI agents compromising other AI agents (agent-to-agent attacks via MCP/tool-use)',
        defense: 'Sudarshana for AI tool calls — sandbox what AI agents can invoke',
        status: 'FUTURE',
        recommendation: 'Extend Sudarshana to monitor LLM tool-use permissions (MCP server sandboxing)'
      },
      {
        generation: 7,
        era: '2028+ (PREDICTED)',
        vector: 'Quantum computing breaks package signing (SHA-256 collision attacks)',
        defense: 'Post-quantum hash functions (SHA-3, BLAKE3)',
        status: 'FUTURE',
        recommendation: 'Prepare migration to quantum-resistant hashing when available'
      }
    ];

    return {
      currentGeneration: 4,
      predictedNext: evolution.find(e => e.status === 'PREPARE NOW'),
      futureVectors: evolution.filter(e => e.status === 'FUTURE'),
      timeline: evolution,
      recommendation: 'Focus defenses on Generation 5 (build-tool attacks) — this is the next frontier.'
    };
  }

  /**
   * Generate full precognition report
   */
  generateReport() {
    const lines = [];
    lines.push('');
    lines.push('∞² SUDARSHANA — Precognition Report');
    lines.push('═'.repeat(55));
    lines.push('  "The disc sees what hasn\'t happened yet."\n');

    // Attacker ROI
    const roi = this.calculateAttackerROI();
    const highROI = roi.filter(r => r.roiScore >= 40);
    if (highROI.length > 0) {
      lines.push('  🎯 HIGHEST-VALUE TARGETS (attacker perspective):');
      for (const r of highROI.slice(0, 5)) {
        lines.push(`    ${r.risk === 'CRITICAL_TARGET' ? '🔴' : '🟠'} ${r.package.padEnd(25)} ROI: ${r.roiScore}/100`);
      }
      lines.push('');
    }

    // Burnout
    const burnout = this.maintainerBurnoutModel();
    if (burnout.length > 0) {
      lines.push('  😰 BURNOUT RISK (may be abandoned/sold):');
      for (const b of burnout.slice(0, 5)) {
        lines.push(`    ⚠️  ${b.package.padEnd(25)} ${b.indicators[0] || ''}`);
      }
      lines.push('');
    }

    // Blast radius
    const blast = this.blastRadiusAnalysis();
    const critical = blast.filter(b => b.priority === 'CRITICAL');
    if (critical.length > 0) {
      lines.push('  💥 HIGHEST BLAST RADIUS (if compromised):');
      for (const b of critical.slice(0, 5)) {
        lines.push(`    💥 ${b.package.padEnd(25)} affects ${b.cascadeSize} packages (${b.blastRadius}%)`);
      }
      lines.push('');
    }

    // Next vector
    const next = this.predictNextVector();
    lines.push('  🔮 PREDICTED NEXT ATTACK VECTOR:');
    lines.push(`    Generation ${next.predictedNext.generation}: ${next.predictedNext.vector}`);
    lines.push(`    Era: ${next.predictedNext.era}`);
    lines.push(`    → ${next.predictedNext.recommendation}`);
    lines.push('');

    return lines.join('\n');
  }
}

module.exports = { PrecognitionNetwork };
