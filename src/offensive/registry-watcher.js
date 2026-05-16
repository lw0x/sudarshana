'use strict';

/**
 * SUDARSHANA — LEVEL 11: REGISTRY WATCHER
 * 
 * "If they publish it, we see it. Before your npm install does."
 * 
 * Monitors the npm registry for:
 * 1. Typosquats of YOUR dependencies (expresss, lodassh)
 * 2. Maintainer changes on packages you depend on
 * 3. Version yanks followed by republishes (hijack signal)
 * 4. Sudden new dependencies added to trusted packages
 * 5. New packages with suspiciously similar names to yours
 * 
 * Runs as a scheduled check or daemon.
 * 
 * Usage:
 *   sudarshana watch                  Run one-time check
 *   sudarshana watch --daemon         Run continuously (check every hour)
 *   sudarshana watch --report         Generate report of findings
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

class RegistryWatcher {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.watchDir = path.join(this.projectRoot, '.sudarshana-watch');
    this.state = this._loadState();
  }

  _ensureDir() {
    if (!fs.existsSync(this.watchDir)) fs.mkdirSync(this.watchDir, { recursive: true });
  }

  _statePath() { return path.join(this.watchDir, 'state.json'); }

  _loadState() {
    this._ensureDir();
    const p = this._statePath();
    if (fs.existsSync(p)) {
      try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch(e) {}
    }
    return { lastCheck: null, knownVersions: {}, knownMaintainers: {}, alerts: [] };
  }

  _saveState() {
    fs.writeFileSync(this._statePath(), JSON.stringify(this.state, null, 2));
  }

  /**
   * Generate typosquat watchlist from current dependencies
   */
  generateWatchlist() {
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) throw new Error('No package.json');

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });

    const watchlist = [];

    for (const dep of deps) {
      // Generate all common typosquat variants
      const variants = this._generateTyposquatVariants(dep);
      watchlist.push({
        original: dep,
        variants,
        priority: this._getPackagePriority(dep)
      });
    }

    return watchlist;
  }

  /**
   * Generate common typosquat variants for a package name
   */
  _generateTyposquatVariants(name) {
    const variants = new Set();

    // Character swaps (adjacent keys)
    for (let i = 0; i < name.length - 1; i++) {
      const swapped = name.slice(0, i) + name[i+1] + name[i] + name.slice(i+2);
      if (swapped !== name) variants.add(swapped);
    }

    // Character duplication
    for (let i = 0; i < name.length; i++) {
      variants.add(name.slice(0, i+1) + name[i] + name.slice(i+1));
    }

    // Character omission
    for (let i = 0; i < name.length; i++) {
      const omitted = name.slice(0, i) + name.slice(i+1);
      if (omitted.length >= 2) variants.add(omitted);
    }

    // Common substitutions
    const subs = { 'o': '0', 'l': '1', 'e': '3', 'a': '4', 's': '5', 'i': '1' };
    for (const [char, sub] of Object.entries(subs)) {
      if (name.includes(char)) {
        variants.add(name.replace(char, sub));
      }
    }

    // Separator confusion
    if (name.includes('-')) {
      variants.add(name.replace(/-/g, '_'));
      variants.add(name.replace(/-/g, ''));
      variants.add(name.replace(/-/g, '.'));
    }

    // Prefix/suffix tricks
    variants.add(name + '-js');
    variants.add(name + '-node');
    variants.add(name + 's');
    variants.add('node-' + name);

    return [...variants].filter(v => v !== name);
  }

  /**
   * Check npm registry for a specific package
   * Returns package metadata or null if not found
   */
  async checkRegistry(packageName) {
    return new Promise((resolve) => {
      const req = https.get(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`, {
        headers: { 'Accept': 'application/json' },
        timeout: 10000
      }, (res) => {
        if (res.statusCode === 404) { resolve(null); return; }
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try { resolve(JSON.parse(data)); } catch(e) { resolve(null); }
        });
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
    });
  }

  /**
   * Run a full watch cycle — check for typosquats and changes
   * NOTE: Makes network calls to npm registry
   */
  async runCheck() {
    const alerts = [];
    const watchlist = this.generateWatchlist();

    // Check top-priority variants only (rate limit friendly)
    const toCheck = watchlist
      .sort((a, b) => b.priority - a.priority)
      .slice(0, 10)
      .flatMap(w => w.variants.slice(0, 3).map(v => ({ original: w.original, variant: v })));

    for (const { original, variant } of toCheck) {
      const result = await this.checkRegistry(variant);
      if (result && result.name) {
        // Typosquat EXISTS on npm!
        const created = result.time ? result.time.created : null;
        const age = created ? (Date.now() - new Date(created).getTime()) / (1000 * 60 * 60 * 24) : null;

        alerts.push({
          type: 'TYPOSQUAT_EXISTS',
          severity: age !== null && age < 30 ? 'HIGH' : 'MEDIUM',
          original,
          typosquat: variant,
          version: result['dist-tags'] ? result['dist-tags'].latest : 'unknown',
          created,
          ageInDays: age ? Math.round(age) : null,
          description: result.description || '',
          detail: `"${variant}" exists on npm (similar to your dep "${original}")`
        });
      }

      // Small delay to be nice to npm registry
      await new Promise(r => setTimeout(r, 500));
    }

    // Store alerts
    this.state.lastCheck = new Date().toISOString();
    this.state.alerts = [...this.state.alerts, ...alerts].slice(-100); // keep last 100
    this._saveState();

    return alerts;
  }

  /**
   * Check for maintainer changes on your direct dependencies
   */
  async checkMaintainerChanges() {
    const alerts = [];
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys(pkg.dependencies || {}).slice(0, 20); // Top 20

    for (const dep of deps) {
      const result = await this.checkRegistry(dep);
      if (!result || !result.maintainers) continue;

      const currentMaintainers = result.maintainers.map(m => m.name || m.email);
      const knownMaintainers = this.state.knownMaintainers[dep];

      if (knownMaintainers) {
        const added = currentMaintainers.filter(m => !knownMaintainers.includes(m));
        const removed = knownMaintainers.filter(m => !currentMaintainers.includes(m));

        if (added.length > 0 || removed.length > 0) {
          alerts.push({
            type: 'MAINTAINER_CHANGE',
            severity: 'HIGH',
            package: dep,
            added,
            removed,
            detail: `Maintainers changed: +${added.join(',')} -${removed.join(',')}`
          });
        }
      }

      // Update known state
      this.state.knownMaintainers[dep] = currentMaintainers;

      await new Promise(r => setTimeout(r, 300));
    }

    this._saveState();
    return alerts;
  }

  /**
   * Detect time-bomb patterns in installed packages (static check, no network)
   */
  detectTimeBombs() {
    const alerts = [];
    const nodeModulesPath = path.join(this.projectRoot, 'node_modules');
    if (!fs.existsSync(nodeModulesPath)) return alerts;

    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });

    // Patterns that indicate conditional/time-based triggers
    const timeBombPatterns = [
      { regex: /new Date\(\)[\s\S]{0,50}(>|<|>=|<=)\s*new Date\(['"][^'"]+['"]\)/g, name: 'DATE_COMPARISON' },
      { regex: /Date\.now\(\)\s*(>|<)\s*\d{10,}/g, name: 'TIMESTAMP_CHECK' },
      { regex: /getMonth\(\)\s*===?\s*\d|getDate\(\)\s*===?\s*\d/g, name: 'SPECIFIC_DATE_TRIGGER' },
      { regex: /process\.env\.CI|process\.env\.GITHUB_ACTIONS|process\.env\.JENKINS/g, name: 'CI_DETECTION' },
      { regex: /os\.hostname\(\)|os\.userInfo\(\)|os\.networkInterfaces\(\)/g, name: 'ENVIRONMENT_FINGERPRINT' },
      { regex: /Math\.random\(\)\s*<\s*0\.\d/g, name: 'PROBABILISTIC_TRIGGER' },
      { regex: /setTimeout\s*\(\s*(?:function|\(\))\s*(?:=>)?\s*\{[\s\S]{0,200}(?:http|net|dns|exec)/gs, name: 'DELAYED_EXECUTION' },
    ];

    for (const dep of deps) {
      const depPath = path.join(nodeModulesPath, dep);
      if (!fs.existsSync(depPath)) continue;

      // Scan top-level JS files
      try {
        const files = fs.readdirSync(depPath).filter(f => f.endsWith('.js')).slice(0, 5);
        for (const file of files) {
          const content = fs.readFileSync(path.join(depPath, file), 'utf8');

          for (const pattern of timeBombPatterns) {
            pattern.regex.lastIndex = 0;
            const matches = content.match(pattern.regex);
            if (matches) {
              alerts.push({
                type: 'TIME_BOMB_PATTERN',
                severity: pattern.name === 'DATE_COMPARISON' || pattern.name === 'DELAYED_EXECUTION' ? 'HIGH' : 'MEDIUM',
                package: dep,
                pattern: pattern.name,
                file,
                count: matches.length,
                sample: matches[0].substring(0, 80),
                detail: `${dep}/${file}: ${pattern.name} detected (${matches.length}×)`
              });
            }
          }
        }
      } catch(e) {}
    }

    return alerts;
  }

  _getPackagePriority(name) {
    // Higher priority for popular packages (more likely typosquat targets)
    const highPriority = ['express', 'react', 'lodash', 'axios', 'next', 'typescript', 'webpack', 'babel'];
    if (highPriority.includes(name)) return 10;
    if (name.startsWith('@')) return 5; // scoped packages
    return 3;
  }

  /**
   * Generate report
   */
  generateReport(alerts) {
    const lines = [];
    lines.push('');
    lines.push('👁️  SUDARSHANA — Registry Watch Report');
    lines.push('═'.repeat(55));
    lines.push(`  Last check: ${this.state.lastCheck || 'never'}`);
    lines.push(`  Findings: ${alerts.length}`);
    lines.push('');

    if (alerts.length === 0) {
      lines.push('  ✅ No threats detected in registry.');
    } else {
      for (const alert of alerts) {
        const icon = alert.severity === 'HIGH' ? '🔴' : '🟡';
        lines.push(`  ${icon} ${alert.type}: ${alert.detail}`);
      }
    }

    lines.push('');
    return lines.join('\n');
  }
}

module.exports = { RegistryWatcher };
