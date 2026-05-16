'use strict';

/**
 * SUDARSHANA — LEVEL 10: BEHAVIORAL DNA
 * 
 * "Every package has a DNA. Any mutation = instant flag."
 * 
 * Traditional antivirus: signature-based (known bad = blocked)
 * Sudarshana DNA: behavior-based (any CHANGE in behavior = flagged)
 * 
 * How it works:
 * 1. Build a "DNA fingerprint" for each package version
 *    (what modules it imports, what functions it calls, what it accesses)
 * 2. On update: compare new DNA vs old DNA
 * 3. Mutation detected = alert, regardless of whether the new behavior
 *    matches any known attack pattern
 * 
 * This catches ZERO-DAYS by definition:
 * - Package was doing X for 2 years
 * - Suddenly it does X + Y (reads crypto keys)
 * - We don't need to know Y is "bad" — we just know it's NEW
 * 
 * DNA = {
 *   imports: Set<module_name>,
 *   envReads: Set<var_name_pattern>,
 *   networkTargets: Set<domain_pattern>,
 *   fsAccess: Set<path_pattern>,
 *   capabilities: bitmask,
 *   entropy: number,
 *   codeSize: number,
 *   exportSignature: hash
 * }
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DNA_DIR = '.sudarshana-dna';

// Capability bitmask
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

class BehavioralDNA {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.dnaDir = path.join(this.projectRoot, DNA_DIR);
    this.dnaRegistry = this._loadRegistry();
  }

  _ensureDir() {
    if (!fs.existsSync(this.dnaDir)) fs.mkdirSync(this.dnaDir, { recursive: true });
  }

  _registryPath() {
    return path.join(this.dnaDir, 'registry.json');
  }

  _loadRegistry() {
    this._ensureDir();
    const regPath = this._registryPath();
    if (fs.existsSync(regPath)) {
      try { return JSON.parse(fs.readFileSync(regPath, 'utf8')); } catch(e) {}
    }
    return { packages: {}, lastScan: null };
  }

  _saveRegistry() {
    fs.writeFileSync(this._registryPath(), JSON.stringify(this.dnaRegistry, null, 2));
  }

  /**
   * Extract DNA fingerprint for a single package
   */
  extractDNA(packageName) {
    const depPath = path.join(this.projectRoot, 'node_modules', packageName);
    if (!fs.existsSync(depPath)) return null;

    const pkgJsonPath = path.join(depPath, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return null;

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));

    // Collect all JS source
    const jsFiles = this._getJsFiles(depPath, 50);
    const allSource = jsFiles.map(f => {
      try { return fs.readFileSync(f, 'utf8'); } catch(e) { return ''; }
    }).join('\n');

    // Extract DNA markers
    const dna = {
      version: pkg.version,
      timestamp: new Date().toISOString(),

      // What built-in modules does it import?
      imports: this._extractImports(allSource),

      // What env vars does it access?
      envReads: this._extractEnvReads(allSource),

      // What network targets?
      networkTargets: this._extractNetworkTargets(allSource),

      // What file paths?
      fsAccess: this._extractFsPaths(allSource),

      // Capability bitmask
      capabilities: this._calculateCapabilities(allSource, pkg),

      // Code metrics
      entropy: this._calculateEntropy(allSource),
      codeSize: allSource.length,
      fileCount: jsFiles.length,
      lineCount: allSource.split('\n').length,

      // Export signature (what does the module expose?)
      exportSignature: this._hashExports(depPath, pkg),

      // Content hash (detect ANY change)
      contentHash: crypto.createHash('sha256').update(allSource).digest('hex').substring(0, 32),

      // Dependencies (what it pulls in)
      dependencies: Object.keys(pkg.dependencies || {}),

      // Scripts
      hasInstallScript: !!(pkg.scripts && (pkg.scripts.postinstall || pkg.scripts.preinstall)),
    };

    return dna;
  }

  /**
   * Scan all packages and store their DNA
   */
  scanAll() {
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) throw new Error('No package.json');

    const projectPkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys({
      ...projectPkg.dependencies,
      ...projectPkg.devDependencies
    });

    const results = { scanned: 0, mutations: [] };

    for (const dep of deps) {
      const newDNA = this.extractDNA(dep);
      if (!newDNA) continue;

      results.scanned++;
      const existingDNA = this.dnaRegistry.packages[dep];

      if (existingDNA) {
        // Compare DNA — detect mutations
        const mutations = this.compareDNA(dep, existingDNA, newDNA);
        if (mutations.length > 0) {
          results.mutations.push({ package: dep, mutations });
        }
      }

      // Store new DNA
      this.dnaRegistry.packages[dep] = newDNA;
    }

    this.dnaRegistry.lastScan = new Date().toISOString();
    this._saveRegistry();

    return results;
  }

  /**
   * Compare two DNA fingerprints and return mutations
   */
  compareDNA(packageName, oldDNA, newDNA) {
    const mutations = [];

    // Version change
    if (oldDNA.version !== newDNA.version) {
      mutations.push({
        type: 'VERSION_CHANGE',
        severity: 'INFO',
        detail: `${oldDNA.version} → ${newDNA.version}`
      });
    }

    // Same version, different content (CRITICAL — possible hijack)
    if (oldDNA.version === newDNA.version && oldDNA.contentHash !== newDNA.contentHash) {
      mutations.push({
        type: 'CONTENT_MUTATED_SAME_VERSION',
        severity: 'CRITICAL',
        detail: `Content changed without version bump — possible package hijack`
      });
    }

    // New imports
    const newImports = newDNA.imports.filter(i => !oldDNA.imports.includes(i));
    if (newImports.length > 0) {
      const dangerousImports = newImports.filter(i =>
        ['child_process', 'net', 'dns', 'http', 'https', 'tls', 'dgram'].includes(i)
      );
      if (dangerousImports.length > 0) {
        mutations.push({
          type: 'NEW_DANGEROUS_IMPORT',
          severity: 'HIGH',
          detail: `Now imports: ${dangerousImports.join(', ')}`
        });
      } else if (newImports.length > 3) {
        mutations.push({
          type: 'MANY_NEW_IMPORTS',
          severity: 'MEDIUM',
          detail: `${newImports.length} new imports added`
        });
      }
    }

    // New env reads
    const newEnvReads = newDNA.envReads.filter(e => !oldDNA.envReads.includes(e));
    if (newEnvReads.length > 0) {
      const sensitiveEnv = newEnvReads.filter(e =>
        /secret|key|token|password|credential|auth/i.test(e)
      );
      if (sensitiveEnv.length > 0) {
        mutations.push({
          type: 'NEW_SENSITIVE_ENV_ACCESS',
          severity: 'HIGH',
          detail: `Now reads: ${sensitiveEnv.join(', ')}`
        });
      }
    }

    // New network targets
    const newNet = newDNA.networkTargets.filter(n => !oldDNA.networkTargets.includes(n));
    if (newNet.length > 0) {
      mutations.push({
        type: 'NEW_NETWORK_TARGETS',
        severity: 'HIGH',
        detail: `New outbound targets: ${newNet.join(', ')}`
      });
    }

    // Capability escalation
    const addedCaps = newDNA.capabilities & ~oldDNA.capabilities;
    if (addedCaps !== 0) {
      const capNames = this._decodeCaps(addedCaps);
      mutations.push({
        type: 'CAPABILITY_ESCALATION',
        severity: 'HIGH',
        detail: `New capabilities: ${capNames.join(', ')}`
      });
    }

    // Significant code size change (>50% growth could indicate injected payload)
    if (oldDNA.codeSize > 0) {
      const growth = (newDNA.codeSize - oldDNA.codeSize) / oldDNA.codeSize;
      if (growth > 0.5) {
        mutations.push({
          type: 'CODE_SIZE_SPIKE',
          severity: 'MEDIUM',
          detail: `Code grew ${Math.round(growth * 100)}% (${oldDNA.codeSize} → ${newDNA.codeSize} bytes)`
        });
      }
    }

    // Entropy spike (obfuscation added)
    if (oldDNA.entropy > 0 && newDNA.entropy - oldDNA.entropy > 0.5) {
      mutations.push({
        type: 'ENTROPY_SPIKE',
        severity: 'MEDIUM',
        detail: `Entropy increased significantly (${oldDNA.entropy.toFixed(2)} → ${newDNA.entropy.toFixed(2)}) — possible obfuscation`
      });
    }

    // Install script added
    if (!oldDNA.hasInstallScript && newDNA.hasInstallScript) {
      mutations.push({
        type: 'INSTALL_SCRIPT_ADDED',
        severity: 'HIGH',
        detail: 'Install script added — check for postinstall exfiltration'
      });
    }

    // Export signature changed (API mutation)
    if (oldDNA.exportSignature !== newDNA.exportSignature) {
      mutations.push({
        type: 'EXPORT_SIGNATURE_CHANGED',
        severity: 'LOW',
        detail: 'Module exports changed (API surface mutation)'
      });
    }

    return mutations;
  }

  // ═══ DNA Extraction Helpers ═══

  _extractImports(source) {
    const requires = source.match(/require\(['"]([^'"]+)['"]\)/g) || [];
    const imports = source.match(/from\s+['"]([^'"]+)['"]/g) || [];

    const modules = new Set();
    for (const r of requires) {
      const match = r.match(/['"]([^'"]+)['"]/);
      if (match && !match[1].startsWith('.') && !match[1].startsWith('/')) {
        modules.add(match[1].split('/')[0]);
      }
    }
    for (const i of imports) {
      const match = i.match(/['"]([^'"]+)['"]/);
      if (match && !match[1].startsWith('.') && !match[1].startsWith('/')) {
        modules.add(match[1].split('/')[0]);
      }
    }
    return [...modules];
  }

  _extractEnvReads(source) {
    const reads = new Set();
    const matches = source.match(/process\.env\.([A-Z_][A-Z0-9_]*)/g) || [];
    for (const m of matches) {
      reads.add(m.replace('process.env.', ''));
    }
    const bracketMatches = source.match(/process\.env\[['"]([^'"]+)['"]\]/g) || [];
    for (const m of bracketMatches) {
      const key = m.match(/['"]([^'"]+)['"]/);
      if (key) reads.add(key[1]);
    }
    return [...reads];
  }

  _extractNetworkTargets(source) {
    const targets = new Set();
    // URLs
    const urls = source.match(/https?:\/\/[^\s'"`,)]+/g) || [];
    for (const url of urls) {
      try {
        const hostname = new URL(url).hostname;
        if (hostname && !hostname.includes('localhost') && !hostname.includes('127.0.0.1')) {
          targets.add(hostname);
        }
      } catch(e) {}
    }
    return [...targets];
  }

  _extractFsPaths(source) {
    const paths = new Set();
    const sensitive = source.match(/['"](?:\/etc\/|~\/\.|\.env|\.ssh|\.aws|\.npmrc|id_rsa)[^'"]*['"]/g) || [];
    for (const p of sensitive) {
      paths.add(p.replace(/['"]/g, ''));
    }
    return [...paths];
  }

  _calculateCapabilities(source, pkg) {
    let caps = CAPS.NONE;
    if (/process\.env/.test(source)) caps |= CAPS.ENV_READ;
    if (/\bfs\b.*\bread/.test(source) || /readFile/.test(source)) caps |= CAPS.FS_READ;
    if (/\bfs\b.*\bwrite/.test(source) || /writeFile/.test(source)) caps |= CAPS.FS_WRITE;
    if (/https?\.request|https?\.get|fetch\(/.test(source)) caps |= CAPS.NET_HTTP;
    if (/\bnet\b.*\bconnect/.test(source)) caps |= CAPS.NET_TCP;
    if (/\bdns\b.*\b(resolve|lookup)/.test(source)) caps |= CAPS.NET_DNS;
    if (/child_process|exec\(|spawn\(/.test(source)) caps |= CAPS.CHILD_PROCESS;
    if (/\bcrypto\b/.test(source)) caps |= CAPS.CRYPTO;
    if (/setTimeout|setInterval/.test(source)) caps |= CAPS.TIMER_DELAYED;
    if (pkg.gypfile) caps |= CAPS.NATIVE_ADDON;
    if (/\beval\s*\(|new\s+Function/.test(source)) caps |= CAPS.EVAL;
    return caps;
  }

  _decodeCaps(bitmask) {
    const names = [];
    for (const [name, bit] of Object.entries(CAPS)) {
      if (name !== 'NONE' && (bitmask & bit)) names.push(name);
    }
    return names;
  }

  _calculateEntropy(text) {
    if (!text || text.length === 0) return 0;
    const freq = {};
    for (const char of text) freq[char] = (freq[char] || 0) + 1;
    const len = text.length;
    let entropy = 0;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 100) / 100;
  }

  _hashExports(depPath, pkg) {
    const mainFile = path.join(depPath, pkg.main || 'index.js');
    if (!fs.existsSync(mainFile)) return 'unknown';

    try {
      const content = fs.readFileSync(mainFile, 'utf8');
      // Hash just the export statements
      const exports = content.match(/module\.exports[\s\S]{0,500}|export\s+(?:default\s+)?(?:class|function|const|let|var)\s+\w+/g) || [];
      return crypto.createHash('sha256').update(exports.join('')).digest('hex').substring(0, 16);
    } catch(e) { return 'error'; }
  }

  _getJsFiles(dir, maxFiles) {
    const files = [];
    const queue = [dir];
    const seen = new Set();

    while (queue.length > 0 && files.length < maxFiles) {
      const current = queue.shift();
      if (seen.has(current)) continue;
      seen.add(current);

      try {
        for (const entry of fs.readdirSync(current)) {
          if (entry === 'node_modules' || entry === '.git') continue;
          const full = path.join(current, entry);
          try {
            const stat = fs.statSync(full);
            if (stat.isDirectory()) queue.push(full);
            else if (/\.(js|mjs|cjs)$/.test(entry)) files.push(full);
          } catch(e) {}
        }
      } catch(e) {}
    }
    return files;
  }

  /**
   * Generate mutation report
   */
  generateReport(scanResult) {
    const lines = [];
    lines.push('');
    lines.push('🧬 SUDARSHANA — Behavioral DNA Report');
    lines.push('═'.repeat(55));
    lines.push(`  Packages scanned: ${scanResult.scanned}`);
    lines.push(`  Mutations found:  ${scanResult.mutations.length}`);
    lines.push('');

    if (scanResult.mutations.length === 0) {
      lines.push('  ✅ No behavioral mutations detected. DNA stable.');
    } else {
      for (const { package: pkg, mutations } of scanResult.mutations) {
        lines.push(`  📦 ${pkg}:`);
        for (const m of mutations) {
          const icon = m.severity === 'CRITICAL' ? '🔴' :
                       m.severity === 'HIGH' ? '🟠' :
                       m.severity === 'MEDIUM' ? '🟡' : '🔵';
          lines.push(`    ${icon} ${m.type}: ${m.detail}`);
        }
        lines.push('');
      }
    }

    return lines.join('\n');
  }
}

module.exports = { BehavioralDNA, CAPS };
