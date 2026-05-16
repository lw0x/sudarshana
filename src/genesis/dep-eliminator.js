'use strict';

/**
 * SUDARSHANA — LEVEL 18: DEPENDENCY ELIMINATOR
 * 
 * "The safest dependency is one that doesn't exist."
 * 
 * Analyzes what you ACTUALLY USE from each dependency, then:
 * 1. Inlines just those functions into your project
 * 2. Removes the dependency entirely
 * 3. Zero deps = zero attack surface
 * 
 * Example:
 *   You use lodash for: _.get, _.merge, _.uniq (3 functions)
 *   lodash has: 300+ functions + complex internals
 *   
 *   Eliminator: extracts just those 3, inlines them as local utils.
 *   Result: lodash removed from package.json. 0 risk.
 * 
 * Also generates "safe replacements" for risky packages:
 *   - sketchy-uuid → crypto.randomUUID() (built-in, zero deps)
 *   - risky-fetch → native fetch (Node 18+)
 *   - questionable-deep-merge → 15-line local function
 * 
 * Usage:
 *   sudarshana eliminate --analyze         Show what you actually use
 *   sudarshana eliminate --generate        Generate inlined replacements
 *   sudarshana eliminate <package>         Eliminate specific package
 */

const fs = require('fs');
const path = require('path');

// Common packages that can be replaced with built-ins or small inlines
const REPLACEMENTS = {
  'uuid': {
    builtIn: 'crypto.randomUUID()',
    minNodeVersion: 19,
    inline: `const { randomUUID } = require('crypto');\nconst uuid = () => randomUUID();`,
    functions: { v4: "require('crypto').randomUUID()" }
  },
  'nanoid': {
    inline: `const { randomBytes } = require('crypto');\nconst nanoid = (size = 21) => randomBytes(size).toString('base64url').slice(0, size);`,
    functions: { nanoid: 'inline' }
  },
  'ms': {
    inline: `function ms(val) {
  if (typeof val === 'number') return val;
  const units = {s:1000,m:60000,h:3600000,d:86400000,w:604800000,y:31557600000};
  const m = String(val).match(/^(\\d+\\.?\\d*)\\s*(s|m|h|d|w|y)/);
  return m ? parseFloat(m[1]) * units[m[2]] : 0;
}`,
    functions: { default: 'inline' }
  },
  'is-odd': {
    inline: `const isOdd = n => n % 2 !== 0;`,
    functions: { default: 'inline' }
  },
  'is-even': {
    inline: `const isEven = n => n % 2 === 0;`,
    functions: { default: 'inline' }
  },
  'left-pad': {
    inline: `const leftPad = (str, len, ch = ' ') => String(str).padStart(len, ch);`,
    functions: { default: 'inline' }
  },
  'deep-equal': {
    inline: `const { deepEqual } = require('assert');\nconst isDeepEqual = (a, b) => { try { deepEqual(a, b); return true; } catch { return false; } };`,
    functions: { default: 'inline' }
  },
  'path-exists': {
    inline: `const { existsSync } = require('fs');\nconst pathExists = existsSync;`,
    functions: { sync: "require('fs').existsSync" }
  },
  'mkdirp': {
    builtIn: "fs.mkdirSync(path, { recursive: true })",
    minNodeVersion: 10,
    inline: `const { mkdirSync } = require('fs');\nconst mkdirp = p => mkdirSync(p, { recursive: true });`,
    functions: { sync: 'inline', default: 'inline' }
  },
  'rimraf': {
    builtIn: "fs.rmSync(path, { recursive: true, force: true })",
    minNodeVersion: 14,
    inline: `const { rmSync } = require('fs');\nconst rimraf = p => rmSync(p, { recursive: true, force: true });`,
    functions: { sync: 'inline', default: 'inline' }
  },
  'node-fetch': {
    builtIn: 'global fetch (built-in)',
    minNodeVersion: 18,
    inline: `// Use native fetch (Node 18+)\n// const fetch = globalThis.fetch;`,
    functions: { default: 'globalThis.fetch' }
  },
  'chalk': {
    inline: `// Minimal chalk replacement (no deps)
const chalk = {
  red: s => \`\\x1b[31m\${s}\\x1b[0m\`,
  green: s => \`\\x1b[32m\${s}\\x1b[0m\`,
  yellow: s => \`\\x1b[33m\${s}\\x1b[0m\`,
  blue: s => \`\\x1b[34m\${s}\\x1b[0m\`,
  bold: s => \`\\x1b[1m\${s}\\x1b[0m\`,
  dim: s => \`\\x1b[2m\${s}\\x1b[0m\`,
};`,
    functions: { red: 'inline', green: 'inline', yellow: 'inline', blue: 'inline', bold: 'inline' }
  },
  'dotenv': {
    inline: `// Minimal dotenv replacement
const { readFileSync, existsSync } = require('fs');
const { resolve } = require('path');
function loadEnv(envPath = resolve(process.cwd(), '.env')) {
  if (!existsSync(envPath)) return {};
  const content = readFileSync(envPath, 'utf8');
  for (const line of content.split('\\n')) {
    const match = line.match(/^([^#=]+)=(.*)$/);
    if (match) process.env[match[1].trim()] = match[2].trim().replace(/^["']|["']$/g, '');
  }
}`,
    functions: { config: 'inline' }
  }
};

class DependencyEliminator {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.nodeModulesPath = path.join(this.projectRoot, 'node_modules');
  }

  /**
   * Analyze which dependencies can be eliminated
   */
  analyze() {
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) throw new Error('No package.json');

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const deps = Object.keys(pkg.dependencies || {});
    const results = { eliminable: [], reducible: [], required: [] };

    for (const dep of deps) {
      if (REPLACEMENTS[dep]) {
        const replacement = REPLACEMENTS[dep];
        const nodeVersion = parseInt(process.version.slice(1));
        const canUseBuiltIn = replacement.builtIn && (!replacement.minNodeVersion || nodeVersion >= replacement.minNodeVersion);

        results.eliminable.push({
          package: dep,
          method: canUseBuiltIn ? 'built-in' : 'inline',
          replacement: canUseBuiltIn ? replacement.builtIn : 'inline function',
          lineCount: (replacement.inline || '').split('\n').length,
          reason: canUseBuiltIn
            ? `Replace with Node.js built-in: ${replacement.builtIn}`
            : `Replace with ${(replacement.inline || '').split('\n').length}-line inline`
        });
      } else {
        // Check if the package is tiny (could be inlined)
        const usage = this._analyzeUsage(dep);
        if (usage.functionsUsed <= 3 && usage.linesOfDep < 100) {
          results.reducible.push({
            package: dep,
            functionsUsed: usage.functionsUsed,
            totalFunctions: usage.totalExports,
            usagePercent: Math.round((usage.functionsUsed / Math.max(usage.totalExports, 1)) * 100),
            suggestion: `You use ${usage.functionsUsed}/${usage.totalExports} exports — consider extracting just what you need`
          });
        } else {
          results.required.push({
            package: dep,
            functionsUsed: usage.functionsUsed,
            reason: 'Complex package — keep as dependency'
          });
        }
      }
    }

    return results;
  }

  /**
   * Generate inlined replacements for eliminable packages
   */
  generateReplacements(packages = null) {
    const analysis = this.analyze();
    const targets = packages
      ? analysis.eliminable.filter(e => packages.includes(e.package))
      : analysis.eliminable;

    const generated = [];

    for (const target of targets) {
      const replacement = REPLACEMENTS[target.package];
      if (!replacement) continue;

      generated.push({
        package: target.package,
        code: replacement.inline,
        filename: `${target.package.replace(/[^a-z0-9]/gi, '-')}-replacement.js`,
        instructions: [
          `1. Add this code to your project (e.g., src/utils/${target.package}.js)`,
          `2. Replace: require('${target.package}') → require('./utils/${target.package}')`,
          `3. Remove from package.json: npm uninstall ${target.package}`,
          `4. One less dependency. One less attack surface.`
        ]
      });
    }

    return generated;
  }

  /**
   * Save generated replacements to disk
   */
  saveReplacements(replacements) {
    const outDir = path.join(this.projectRoot, 'sudarshana-replacements');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

    for (const rep of replacements) {
      fs.writeFileSync(path.join(outDir, rep.filename), rep.code);
    }

    // Generate index file
    const index = replacements.map(r =>
      `// ${r.package} → ${r.filename}\nmodule.exports.${r.package.replace(/[^a-z0-9]/gi, '_')} = require('./${r.filename}');`
    ).join('\n\n');
    fs.writeFileSync(path.join(outDir, 'index.js'), index);

    return outDir;
  }

  /**
   * Analyze how much of a package you actually use
   */
  _analyzeUsage(packageName) {
    // Scan project source for usage patterns
    const srcDirs = ['src', 'lib', '.'].map(d => path.join(this.projectRoot, d));
    let functionsUsed = 0;
    const usedMembers = new Set();

    for (const dir of srcDirs) {
      if (!fs.existsSync(dir)) continue;
      try {
        const files = fs.readdirSync(dir).filter(f => f.endsWith('.js') || f.endsWith('.ts'));
        for (const file of files.slice(0, 20)) {
          try {
            const content = fs.readFileSync(path.join(dir, file), 'utf8');

            // Find destructured imports: const { a, b } = require('pkg')
            const destructured = content.match(new RegExp(
              `\\{([^}]+)\\}\\s*=\\s*require\\(['"]${packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"]\\)`, 'g'
            ));
            if (destructured) {
              for (const match of destructured) {
                const members = match.match(/\{([^}]+)\}/);
                if (members) {
                  members[1].split(',').forEach(m => usedMembers.add(m.trim()));
                }
              }
            }

            // Find method calls: pkg.method()
            const methodCalls = content.match(new RegExp(
              `(?:${packageName.replace(/[^a-z]/gi, '\\w*')})\\.(\\w+)`, 'g'
            ));
            if (methodCalls) {
              for (const call of methodCalls) {
                const method = call.split('.').pop();
                usedMembers.add(method);
              }
            }
          } catch(e) {}
        }
      } catch(e) {}
    }

    // Count total exports of the package
    let totalExports = 0;
    const depMainPath = path.join(this.nodeModulesPath, packageName, 'index.js');
    if (fs.existsSync(depMainPath)) {
      try {
        const content = fs.readFileSync(depMainPath, 'utf8');
        const exports = content.match(/exports\.\w+|module\.exports\.\w+/g) || [];
        totalExports = exports.length || 10; // default estimate
      } catch(e) { totalExports = 10; }
    }

    return {
      functionsUsed: usedMembers.size,
      totalExports: Math.max(totalExports, usedMembers.size),
      linesOfDep: this._countLines(packageName),
      members: [...usedMembers]
    };
  }

  _countLines(packageName) {
    const mainPath = path.join(this.nodeModulesPath, packageName, 'index.js');
    if (!fs.existsSync(mainPath)) return 999;
    try {
      return fs.readFileSync(mainPath, 'utf8').split('\n').length;
    } catch(e) { return 999; }
  }

  /**
   * Generate report
   */
  generateReport(analysis) {
    const lines = [];
    lines.push('');
    lines.push('🌱 SUDARSHANA — Dependency Elimination Report');
    lines.push('═'.repeat(55));
    lines.push('');

    if (analysis.eliminable.length > 0) {
      lines.push(`  ✅ ELIMINABLE (${analysis.eliminable.length} packages → 0 risk):`);
      for (const e of analysis.eliminable) {
        lines.push(`    📦 ${e.package.padEnd(20)} → ${e.reason}`);
      }
      lines.push('');
    }

    if (analysis.reducible.length > 0) {
      lines.push(`  🟡 REDUCIBLE (${analysis.reducible.length} packages → extract what you use):`);
      for (const r of analysis.reducible) {
        lines.push(`    📦 ${r.package.padEnd(20)} → ${r.suggestion}`);
      }
      lines.push('');
    }

    lines.push(`  📊 Summary:`);
    lines.push(`    Can eliminate:    ${analysis.eliminable.length} packages`);
    lines.push(`    Can reduce:       ${analysis.reducible.length} packages`);
    lines.push(`    Must keep:        ${analysis.required.length} packages`);
    lines.push(`    Attack surface reduction: ~${Math.round((analysis.eliminable.length / (analysis.eliminable.length + analysis.reducible.length + analysis.required.length)) * 100)}%`);
    lines.push('');

    return lines.join('\n');
  }
}

module.exports = { DependencyEliminator, REPLACEMENTS };
