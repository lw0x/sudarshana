'use strict';

/**
 * SUDARSHANA — LEVEL 15: POLYGLOT ENGINE (Language-Agnostic)
 * 
 * "Not just npm. Every ecosystem. One disc rules them all."
 * 
 * Extends Sudarshana's philosophy to:
 * - Python (PyPI) — pip install scanning
 * - Ruby (RubyGems) — gem install scanning
 * - Go (modules) — go get scanning
 * - Rust (crates.io) — cargo add scanning
 * - Java (Maven/Gradle) — dependency scanning
 * 
 * Each ecosystem adapter implements:
 * 1. Package manifest parsing (requirements.txt, Gemfile, go.mod, etc.)
 * 2. Dependency tree resolution
 * 3. Static scanning (same patterns, language-adapted regex)
 * 4. Behavioral fingerprinting
 * 5. Policy generation
 * 
 * The architecture is plugin-based:
 * sudarshana --ecosystem=python scan
 * sudarshana --ecosystem=ruby scan
 */

const fs = require('fs');
const path = require('path');

// Ecosystem-specific configurations
const ECOSYSTEMS = {
  npm: {
    name: 'npm (Node.js)',
    manifest: 'package.json',
    lockfiles: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
    registry: 'https://registry.npmjs.org',
    installCmd: 'npm install',
    dangerousPatterns: {
      codeExecution: /\beval\s*\(|new\s+Function\s*\(|child_process/g,
      networkAccess: /require\(['"](?:http|https|net|dns|dgram)['"]\)/g,
      fileAccess: /require\(['"]fs['"]\)|readFileSync|writeFileSync/g,
      envAccess: /process\.env/g,
      obfuscation: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}|eval\(atob\(/gi,
    }
  },

  python: {
    name: 'PyPI (Python)',
    manifest: 'requirements.txt',
    lockfiles: ['Pipfile.lock', 'poetry.lock'],
    altManifests: ['setup.py', 'setup.cfg', 'pyproject.toml'],
    registry: 'https://pypi.org',
    installCmd: 'pip install',
    dangerousPatterns: {
      codeExecution: /\bexec\s*\(|\beval\s*\(|subprocess\.(run|call|Popen|check_output)|os\.system\s*\(/g,
      networkAccess: /import\s+(requests|urllib|httpx|aiohttp|socket)|from\s+(requests|urllib|httpx)/g,
      fileAccess: /open\s*\(|os\.path|pathlib|shutil\.(copy|move|rmtree)/g,
      envAccess: /os\.environ|os\.getenv/g,
      obfuscation: /exec\s*\(\s*(?:base64\.b64decode|codecs\.decode|bytes\.fromhex)/g,
      installHook: /setup\(\s*[^)]*cmdclass|__import__\s*\(\s*['"]os['"]\)/g,
    }
  },

  ruby: {
    name: 'RubyGems (Ruby)',
    manifest: 'Gemfile',
    lockfiles: ['Gemfile.lock'],
    registry: 'https://rubygems.org',
    installCmd: 'gem install',
    dangerousPatterns: {
      codeExecution: /\beval\s*\(|`[^`]+`|system\s*\(|%x\{|Kernel\.exec/g,
      networkAccess: /require\s+['"]net\/http|require\s+['"]open-uri|require\s+['"]socket/g,
      fileAccess: /File\.(read|write|open|delete)|Dir\.(glob|entries)|FileUtils/g,
      envAccess: /ENV\[/g,
      obfuscation: /eval\s*\(\s*Base64\.decode64/g,
    }
  },

  go: {
    name: 'Go Modules',
    manifest: 'go.mod',
    lockfiles: ['go.sum'],
    registry: 'https://proxy.golang.org',
    installCmd: 'go get',
    dangerousPatterns: {
      codeExecution: /exec\.Command|os\/exec|syscall\.Exec/g,
      networkAccess: /net\/http|net\.Dial|net\.Listen/g,
      fileAccess: /os\.(Open|Create|ReadFile|WriteFile|Remove)|ioutil\.(ReadFile|WriteFile)/g,
      envAccess: /os\.Getenv|os\.LookupEnv/g,
      obfuscation: /encoding\/base64.*Decode|hex\.DecodeString/g,
    }
  },

  rust: {
    name: 'Crates.io (Rust)',
    manifest: 'Cargo.toml',
    lockfiles: ['Cargo.lock'],
    registry: 'https://crates.io',
    installCmd: 'cargo add',
    dangerousPatterns: {
      codeExecution: /std::process::Command|unsafe\s*\{/g,
      networkAccess: /use\s+(?:reqwest|hyper|tokio::net|std::net)/g,
      fileAccess: /std::fs::|std::io::|File::(?:open|create)/g,
      envAccess: /std::env::var|env::var_os/g,
      obfuscation: /include_bytes!|include_str!/g,
    }
  },

  java: {
    name: 'Maven/Gradle (Java)',
    manifest: 'pom.xml',
    altManifests: ['build.gradle', 'build.gradle.kts'],
    lockfiles: [],
    registry: 'https://repo1.maven.org/maven2',
    installCmd: 'mvn install',
    dangerousPatterns: {
      codeExecution: /Runtime\.getRuntime\(\)\.exec|ProcessBuilder|ScriptEngine/g,
      networkAccess: /java\.net\.(URL|HttpURLConnection|Socket)|okhttp|HttpClient/g,
      fileAccess: /java\.io\.File|Files\.(read|write|delete|copy)|FileInputStream/g,
      envAccess: /System\.getenv|System\.getProperty/g,
      obfuscation: /Base64\.getDecoder|DatatypeConverter\.parseBase64/g,
    }
  }
};

class PolyglotEngine {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
  }

  /**
   * Auto-detect which ecosystem(s) this project uses
   */
  detectEcosystems() {
    const detected = [];

    for (const [id, eco] of Object.entries(ECOSYSTEMS)) {
      const manifestPath = path.join(this.projectRoot, eco.manifest);
      if (fs.existsSync(manifestPath)) {
        detected.push({ id, ...eco });
        continue;
      }
      // Check alt manifests
      if (eco.altManifests) {
        for (const alt of eco.altManifests) {
          if (fs.existsSync(path.join(this.projectRoot, alt))) {
            detected.push({ id, ...eco, detectedVia: alt });
            break;
          }
        }
      }
    }

    return detected;
  }

  /**
   * Scan a file using ecosystem-specific patterns
   */
  scanFile(filePath, ecosystem) {
    const eco = ECOSYSTEMS[ecosystem];
    if (!eco) throw new Error(`Unknown ecosystem: ${ecosystem}`);

    const content = fs.readFileSync(filePath, 'utf8');
    const findings = [];

    for (const [category, regex] of Object.entries(eco.dangerousPatterns)) {
      regex.lastIndex = 0;
      const matches = content.match(regex);
      if (matches) {
        findings.push({
          category,
          pattern: regex.source.substring(0, 50),
          count: matches.length,
          samples: matches.slice(0, 3).map(m => m.substring(0, 80)),
          severity: category === 'codeExecution' || category === 'obfuscation' ? 'CRITICAL' :
                   category === 'networkAccess' ? 'HIGH' : 'MEDIUM'
        });
      }
    }

    return {
      file: filePath,
      ecosystem,
      findings,
      riskScore: findings.reduce((sum, f) => {
        const w = { CRITICAL: 30, HIGH: 15, MEDIUM: 5 };
        return sum + (w[f.severity] || 0) * f.count;
      }, 0)
    };
  }

  /**
   * Parse dependencies from manifest files
   */
  parseDependencies(ecosystem) {
    const eco = ECOSYSTEMS[ecosystem];
    if (!eco) return [];

    const manifestPath = path.join(this.projectRoot, eco.manifest);
    if (!fs.existsSync(manifestPath)) return [];

    const content = fs.readFileSync(manifestPath, 'utf8');

    switch (ecosystem) {
      case 'npm':
        return this._parseNpmDeps(content);
      case 'python':
        return this._parsePythonDeps(content);
      case 'ruby':
        return this._parseRubyDeps(content);
      case 'go':
        return this._parseGoDeps(content);
      case 'rust':
        return this._parseRustDeps(content);
      case 'java':
        return this._parseJavaDeps(content);
      default:
        return [];
    }
  }

  _parseNpmDeps(content) {
    try {
      const pkg = JSON.parse(content);
      return Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })
        .map(([name, version]) => ({ name, version, type: 'npm' }));
    } catch(e) { return []; }
  }

  _parsePythonDeps(content) {
    return content.split('\n')
      .filter(line => line.trim() && !line.startsWith('#'))
      .map(line => {
        const match = line.match(/^([a-zA-Z0-9_-]+)\s*(.*)/);
        return match ? { name: match[1], version: match[2] || '*', type: 'pypi' } : null;
      })
      .filter(Boolean);
  }

  _parseRubyDeps(content) {
    const deps = [];
    const regex = /gem\s+['"]([^'"]+)['"]/g;
    let match;
    while ((match = regex.exec(content)) !== null) {
      deps.push({ name: match[1], version: '*', type: 'rubygems' });
    }
    return deps;
  }

  _parseGoDeps(content) {
    const deps = [];
    const lines = content.split('\n');
    let inRequire = false;
    for (const line of lines) {
      if (line.includes('require (')) { inRequire = true; continue; }
      if (inRequire && line.includes(')')) { inRequire = false; continue; }
      if (inRequire) {
        const match = line.trim().match(/^(\S+)\s+(\S+)/);
        if (match) deps.push({ name: match[1], version: match[2], type: 'go' });
      }
    }
    return deps;
  }

  _parseRustDeps(content) {
    const deps = [];
    const regex = /^(\w[\w-]*)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")/gm;
    let match;
    while ((match = regex.exec(content)) !== null) {
      deps.push({ name: match[1], version: match[2] || match[3], type: 'crates' });
    }
    return deps;
  }

  _parseJavaDeps(content) {
    const deps = [];
    const regex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]*)<\/version>/g;
    let match;
    while ((match = regex.exec(content)) !== null) {
      deps.push({ name: `${match[1]}:${match[2]}`, version: match[3], type: 'maven' });
    }
    return deps;
  }

  /**
   * Generate policy for a non-npm ecosystem
   */
  generatePolicy(ecosystem) {
    const deps = this.parseDependencies(ecosystem);
    const eco = ECOSYSTEMS[ecosystem];

    return {
      ecosystem: eco.name,
      generated: new Date().toISOString(),
      dependencies: deps.length,
      policies: deps.map(dep => ({
        name: dep.name,
        version: dep.version,
        // Default: deny all until learned
        capabilities: {
          network: false,
          filesystem: false,
          shell: false,
          env: false
        }
      }))
    };
  }

  /**
   * Get supported ecosystems info
   */
  getEcosystemInfo() {
    return Object.entries(ECOSYSTEMS).map(([id, eco]) => ({
      id,
      name: eco.name,
      manifest: eco.manifest,
      registry: eco.registry,
      installCmd: eco.installCmd,
      patternCount: Object.keys(eco.dangerousPatterns).length
    }));
  }
}

module.exports = { PolyglotEngine, ECOSYSTEMS };
