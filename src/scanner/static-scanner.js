'use strict';

/**
 * SUDARSHANA — LEVEL 6: STATIC PRE-SCANNER
 * 
 * "See the bullet before it's fired."
 * 
 * Analyzes package source code WITHOUT executing it.
 * Catches:
 * - eval(), Function(), new Function() — code generation
 * - Obfuscated strings (hex, base64, unicode escapes)
 * - Dynamic requires: require(variable)
 * - Encoded payloads hidden in comments/strings
 * - Suspicious patterns: setTimeout + network, conditional triggers
 * 
 * Uses lightweight AST-like parsing (regex + state machine)
 * — no external deps, runs in milliseconds.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Threat patterns (ordered by severity)
const PATTERNS = {
  critical: [
    { name: 'eval_usage', regex: /\beval\s*\(/g, description: 'eval() — arbitrary code execution' },
    { name: 'function_constructor', regex: /new\s+Function\s*\(/g, description: 'new Function() — code generation' },
    { name: 'process_binding', regex: /process\.(binding|dlopen|_linkedBinding)\s*\(/g, description: 'process.binding — low-level access' },
    { name: 'child_process_exec', regex: /\b(execSync|spawnSync|exec)\s*\(\s*[`'"]/g, description: 'Shell execution with string command' },
    { name: 'require_resolve_hook', regex: /Module\._resolveFilename|Module\._load/g, description: 'Module system hooking' },
  ],
  high: [
    { name: 'dynamic_require', regex: /require\s*\(\s*[^'"` ]/g, description: 'Dynamic require (variable path)' },
    { name: 'hex_string_long', regex: /['"]\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){15,}['"]/gi, description: 'Long hex-encoded string' },
    { name: 'base64_long', regex: /['"][A-Za-z0-9+/]{60,}={0,2}['"]/g, description: 'Long base64-encoded string' },
    { name: 'unicode_escape_heavy', regex: /\\u[0-9a-f]{4}(\\u[0-9a-f]{4}){10,}/gi, description: 'Heavy unicode escaping' },
    { name: 'network_in_timeout', regex: /setTimeout\s*\([^)]*(?:http|net|dns|fetch|request)/gs, description: 'Delayed network call (evasion)' },
    { name: 'env_then_network', regex: /process\.env[\s\S]{0,200}(?:https?\.request|fetch|net\.connect)/g, description: 'Env access near network call' },
    { name: 'buffer_from_string', regex: /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/]{40,}/g, description: 'Buffer.from() with encoded payload' },
  ],
  medium: [
    { name: 'process_env_access', regex: /process\.env\[/g, description: 'Dynamic env var access (bracket notation)' },
    { name: 'fs_sensitive_paths', regex: /(?:\.env|\.ssh|\.aws|id_rsa|\.npmrc|\.netrc|shadow|passwd)/g, description: 'References to sensitive paths' },
    { name: 'http_request', regex: /https?\.(?:request|get)\s*\(/g, description: 'HTTP request' },
    { name: 'dns_resolve', regex: /dns\.(?:resolve|lookup)\s*\(/g, description: 'DNS resolution' },
    { name: 'crypto_random', regex: /crypto\.(?:randomBytes|createCipher|createHash)/g, description: 'Crypto usage' },
    { name: 'string_concat_heavy', regex: /(?:\+\s*['"][^'"]{1,3}['"]\s*){5,}/g, description: 'Heavy string concatenation (obfuscation)' },
    { name: 'atob_btoa', regex: /\b(atob|btoa)\s*\(/g, description: 'Base64 encode/decode' },
  ],
  low: [
    { name: 'console_suppression', regex: /console\.(log|warn|error)\s*=\s*/g, description: 'Console method override' },
    { name: 'debugger_statement', regex: /\bdebugger\b/g, description: 'Debugger statement' },
    { name: 'prototype_modify', regex: /\.__proto__|Object\.setPrototypeOf/g, description: 'Prototype modification' },
  ]
};

class StaticScanner {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.nodeModulesPath = path.join(this.projectRoot, 'node_modules');
  }

  /**
   * Scan all direct dependencies
   */
  scanAll(options = {}) {
    const { maxFilesPerPackage = 30, maxFileSize = 500000 } = options;
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) throw new Error('No package.json found');

    const projectPkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys({
      ...projectPkg.dependencies,
      ...projectPkg.devDependencies
    });

    const results = {};
    for (const dep of deps) {
      results[dep] = this.scanPackage(dep, { maxFilesPerPackage, maxFileSize });
    }

    return results;
  }

  /**
   * Scan a single package
   */
  scanPackage(packageName, options = {}) {
    const { maxFilesPerPackage = 30, maxFileSize = 500000 } = options;
    const depPath = path.join(this.nodeModulesPath, packageName);

    if (!fs.existsSync(depPath)) {
      return { error: 'not installed', findings: [] };
    }

    // Collect JS files to scan
    const jsFiles = this._collectJsFiles(depPath, maxFilesPerPackage);
    const findings = [];
    let totalLines = 0;
    let entropy = 0;

    for (const file of jsFiles) {
      try {
        const stat = fs.statSync(file);
        if (stat.size > maxFileSize) continue;

        const content = fs.readFileSync(file, 'utf8');
        const relPath = path.relative(depPath, file);
        totalLines += content.split('\n').length;

        // Run all pattern checks
        for (const [severity, patterns] of Object.entries(PATTERNS)) {
          for (const pattern of patterns) {
            pattern.regex.lastIndex = 0; // Reset regex state
            const matches = content.match(pattern.regex);
            if (matches && matches.length > 0) {
              findings.push({
                severity,
                pattern: pattern.name,
                description: pattern.description,
                file: relPath,
                count: matches.length,
                sample: matches[0].substring(0, 80)
              });
            }
          }
        }

        // Calculate entropy (obfuscation indicator)
        entropy += this._calculateEntropy(content);
      } catch (e) { /* skip unreadable files */ }
    }

    // Average entropy across files
    const avgEntropy = jsFiles.length > 0 ? entropy / jsFiles.length : 0;

    // Obfuscation score (0-100, higher = more obfuscated)
    const obfuscationScore = this._calculateObfuscationScore(jsFiles, depPath);

    // Calculate risk score
    const riskScore = this._calculateRiskScore(findings);

    return {
      package: packageName,
      filesScanned: jsFiles.length,
      totalLines,
      findings,
      riskScore,
      obfuscationScore,
      avgEntropy: Math.round(avgEntropy * 100) / 100,
      summary: {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length
      }
    };
  }

  /**
   * Scan install scripts specifically (the pre-execution threat)
   */
  scanInstallScripts(packageName) {
    const depPath = path.join(this.nodeModulesPath, packageName);
    const pkgJsonPath = path.join(depPath, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return null;

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const scripts = pkg.scripts || {};
    const results = [];

    for (const scriptName of ['preinstall', 'install', 'postinstall']) {
      const script = scripts[scriptName];
      if (!script) continue;

      const threats = [];

      // Check for network commands
      if (/curl|wget|fetch|http|nc\s|ncat/.test(script)) {
        threats.push({ severity: 'critical', detail: 'Network access in install script: ' + script });
      }

      // Check for code execution
      if (/node\s+-e|eval|bash\s+-c|sh\s+-c|python/.test(script)) {
        threats.push({ severity: 'critical', detail: 'Code execution in install script: ' + script });
      }

      // Check for encoded commands
      if (/base64|\\x[0-9a-f]|atob/.test(script)) {
        threats.push({ severity: 'high', detail: 'Encoded content in install script: ' + script });
      }

      // Check for file exfiltration
      if (/cat\s+.*\.env|cat\s+.*\.ssh|cat\s+.*\.aws/.test(script)) {
        threats.push({ severity: 'critical', detail: 'Credential file access in install script: ' + script });
      }

      // Check if script references an external file
      if (/node\s+[^\s]+\.js/.test(script)) {
        const scriptFile = script.match(/node\s+([^\s]+\.js)/);
        if (scriptFile) {
          const scriptPath = path.join(depPath, scriptFile[1]);
          if (fs.existsSync(scriptPath)) {
            // Scan that file too
            const content = fs.readFileSync(scriptPath, 'utf8');
            for (const [severity, patterns] of Object.entries(PATTERNS)) {
              for (const pattern of patterns) {
                pattern.regex.lastIndex = 0;
                if (pattern.regex.test(content)) {
                  threats.push({ severity, detail: `${scriptFile[1]} contains: ${pattern.description}` });
                }
              }
            }
          }
        }
      }

      results.push({ script: scriptName, command: script, threats });
    }

    return results;
  }

  /**
   * Calculate Shannon entropy of text (higher = more random/obfuscated)
   */
  _calculateEntropy(text) {
    if (!text || text.length === 0) return 0;
    const freq = {};
    for (const char of text) {
      freq[char] = (freq[char] || 0) + 1;
    }
    const len = text.length;
    let entropy = 0;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Calculate obfuscation score based on code readability signals
   */
  _calculateObfuscationScore(files, depPath) {
    let score = 0;
    let filesChecked = 0;

    for (const file of files.slice(0, 5)) { // Check first 5 files
      try {
        const content = fs.readFileSync(file, 'utf8');
        const lines = content.split('\n');
        filesChecked++;

        // Average line length (obfuscated code has very long lines)
        const avgLineLen = content.length / lines.length;
        if (avgLineLen > 200) score += 20;
        else if (avgLineLen > 100) score += 10;

        // Single-character variable names ratio
        const varMatches = content.match(/\b[a-z]\b/g) || [];
        const allVars = content.match(/\b[a-z_$][a-z0-9_$]*\b/gi) || [];
        if (allVars.length > 0) {
          const singleCharRatio = varMatches.length / allVars.length;
          if (singleCharRatio > 0.3) score += 15;
        }

        // No comments
        const commentLines = lines.filter(l => l.trim().startsWith('//') || l.trim().startsWith('/*'));
        if (commentLines.length === 0 && lines.length > 50) score += 10;

        // High entropy (random-looking)
        const entropy = this._calculateEntropy(content);
        if (entropy > 5.5) score += 20;
        else if (entropy > 5.0) score += 10;

        // Hex/unicode density
        const hexCount = (content.match(/\\x[0-9a-f]{2}/gi) || []).length;
        const unicodeCount = (content.match(/\\u[0-9a-f]{4}/gi) || []).length;
        if ((hexCount + unicodeCount) / content.length > 0.01) score += 25;

      } catch (e) { /* skip */ }
    }

    return filesChecked > 0 ? Math.min(100, Math.round(score / filesChecked)) : 0;
  }

  /**
   * Calculate overall risk score from findings
   */
  _calculateRiskScore(findings) {
    const weights = { critical: 25, high: 10, medium: 3, low: 1 };
    let score = 0;
    for (const f of findings) {
      score += (weights[f.severity] || 0) * f.count;
    }
    return Math.min(100, score);
  }

  /**
   * Collect JS files from a package directory
   */
  _collectJsFiles(depPath, maxFiles) {
    const files = [];
    const scanDirs = [depPath];
    const seen = new Set();

    while (scanDirs.length > 0 && files.length < maxFiles) {
      const dir = scanDirs.shift();
      if (seen.has(dir)) continue;
      seen.add(dir);

      try {
        const entries = fs.readdirSync(dir);
        for (const entry of entries) {
          if (entry === 'node_modules' || entry === '.git') continue;
          const fullPath = path.join(dir, entry);

          try {
            const stat = fs.statSync(fullPath);
            if (stat.isDirectory()) {
              scanDirs.push(fullPath);
            } else if (entry.endsWith('.js') || entry.endsWith('.mjs') || entry.endsWith('.cjs')) {
              files.push(fullPath);
            }
          } catch (e) { /* skip */ }
        }
      } catch (e) { /* skip */ }
    }

    return files;
  }

  /**
   * Generate scan report
   */
  generateReport(results) {
    const lines = [];
    lines.push('');
    lines.push('🔬 SUDARSHANA — Static Analysis Report');
    lines.push('═'.repeat(55));
    lines.push('');

    const sorted = Object.entries(results)
      .sort(([, a], [, b]) => (b.riskScore || 0) - (a.riskScore || 0));

    for (const [name, data] of sorted) {
      if (data.error) {
        lines.push(`  ⚪ ${name} — ${data.error}`);
        continue;
      }

      const icon = data.riskScore >= 50 ? '🔴' :
                   data.riskScore >= 25 ? '🟠' :
                   data.riskScore >= 10 ? '🟡' : '🟢';

      lines.push(`  ${icon} ${name.padEnd(30)} risk:${String(data.riskScore).padStart(3)} obf:${String(data.obfuscationScore).padStart(3)}`);

      if (data.summary.critical > 0 || data.summary.high > 0) {
        if (data.summary.critical > 0)
          lines.push(`     🔴 ${data.summary.critical} critical findings`);
        if (data.summary.high > 0)
          lines.push(`     🟠 ${data.summary.high} high findings`);

        // Show top findings
        const topFindings = data.findings
          .filter(f => f.severity === 'critical' || f.severity === 'high')
          .slice(0, 3);
        for (const f of topFindings) {
          lines.push(`     └─ ${f.description} (${f.file})`);
        }
      }
    }

    lines.push('');
    return lines.join('\n');
  }
}

module.exports = { StaticScanner, PATTERNS };
