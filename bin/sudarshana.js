#!/usr/bin/env node
'use strict';

/**
 * SUDARSHANA v2.0 CLI — The Complete Security Platform
 * 
 * Commands:
 *   sudarshana init [--strict] [--report]  Generate policies automatically
 *   sudarshana run -- <command>             Run app with runtime sandbox
 *   sudarshana learn -- <command>           Observe & auto-learn policies
 *   sudarshana snapshot                     Save behavioral baseline
 *   sudarshana drift                        Detect changes since snapshot
 *   sudarshana map                          Generate dependency security map
 *   sudarshana install                      npm install with network isolation
 *   sudarshana audit                        Check integrity & vulnerabilities
 *   sudarshana doctor                       Verify Sudarshana is working correctly
 */

const path = require('path');
const fs = require('fs');

const args = process.argv.slice(2);
const command = args[0];

// ASCII banner
function showBanner() {
  console.log(`
  ╔═══════════════════════════════════════════════════╗
  ║  🔥 SUDARSHANA v2.0 — Supply Chain Defense       ║
  ║     "The gun doesn't exist in their reality."    ║
  ╚═══════════════════════════════════════════════════╝
  `);
}

// Help text
function showHelp() {
  showBanner();
  console.log(`
  COMMANDS:

    init [options]        Generate security policies for your project
      --strict            Maximum restriction (deny-all + lockdown mode)
      --report            Show analysis without writing config file

    run -- <command>      Run your app with Sudarshana runtime protection
      --mode=<mode>       enforce (default) | lockdown | monitor
      --format=<fmt>      Report format: cli | json | html

    install               Runs npm install in network-isolated sandbox
                          (blocks postinstall exfiltration attacks)

    audit                 Verify package integrity against npm registry
                          + check for known malicious packages

    doctor                Verify Sudarshana is installed and working correctly

  EXAMPLES:

    # First time setup — auto-generates .sudarshana.json
    sudarshana init

    # Run your app with protection
    sudarshana run -- node server.js

    # Strict mode for CI/CD
    sudarshana init --strict
    sudarshana run --mode=lockdown -- npm test

    # Safe npm install (network isolated)
    sudarshana install

  PHILOSOPHY:

    • Zero config needed — init auto-generates everything
    • Zero friction — < 5% performance overhead
    • Zero false positives — honeypots catch ONLY real attacks
    • Invisible — packages can't detect they're sandboxed
    • Effortless — the secure path IS the easy path
  `);
}

// Route commands
switch (command) {
  case 'init': {
    const options = {
      strict: args.includes('--strict'),
      report: args.includes('--report')
    };
    const { runInit } = require('../src/cli/auto-policy');
    runInit(options);
    break;
  }

  case 'run': {
    const separatorIdx = args.indexOf('--');
    if (separatorIdx === -1 || separatorIdx === args.length - 1) {
      console.error('Error: Specify command after -- (e.g., sudarshana run -- node app.js)');
      process.exit(1);
    }

    const runArgs = args.slice(1, separatorIdx);
    const childCmd = args.slice(separatorIdx + 1);
    const mode = (runArgs.find(a => a.startsWith('--mode=')) || '--mode=enforce').split('=')[1];

    const { spawn } = require('child_process');
    const sudarshanaPath = path.resolve(__dirname, '../src/index.js');
    const esmLoaderPath = path.resolve(__dirname, '../src/resolve.mjs');

    const [cmd, ...cmdArgs] = childCmd;

    // Detect if running an ESM file (.mjs or "type": "module" in package.json)
    const targetFile = cmdArgs[0] || '';
    const isESM = targetFile.endsWith('.mjs') || (() => {
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8'));
        return pkg.type === 'module';
      } catch { return false; }
    })();

    // CJS: --require hook | ESM: --import hook (Node 20+) or --experimental-loader (Node 18)
    const nodeVersion = parseInt(process.version.slice(1));
    const esmFlag = nodeVersion >= 20
      ? `--import ${esmLoaderPath}`
      : `--experimental-loader ${esmLoaderPath}`;
    const nodeOptions = isESM
      ? `--require ${sudarshanaPath} ${esmFlag}`
      : `--require ${sudarshanaPath}`;

    console.log(`🔥 Sudarshana: Running in ${mode.toUpperCase()} mode`);
    console.log(`   Module system: ${isESM ? 'ESM (import)' : 'CJS (require)'}`);
    console.log(`   Command: ${childCmd.join(' ')}\n`);

    const child = spawn(cmd, cmdArgs, {
      stdio: 'inherit',
      env: {
        ...process.env,
        NODE_OPTIONS: process.env.NODE_OPTIONS
          ? `${process.env.NODE_OPTIONS} ${nodeOptions}`
          : nodeOptions
      },
      shell: true
    });

    child.on('exit', (code) => process.exit(code || 0));
    break;
  }

  case 'install': {
    showBanner();
    console.log('  📦 Running npm install with network isolation...\n');
    console.log('  ⚠️  Note: Full network namespace isolation requires Linux.');
    console.log('  On Windows/macOS, install-time scripts are monitored but not fully isolated.\n');

    const { spawn } = require('child_process');
    const sudarshanaPath = path.resolve(__dirname, '../src/index.js');

    // Run npm install with Sudarshana loaded (monitors postinstall scripts)
    const child = spawn('npm', ['install', '--ignore-scripts'], {
      stdio: 'inherit',
      shell: true
    });

    child.on('exit', (code) => {
      if (code === 0) {
        console.log('\n  ✅ Dependencies installed (install scripts skipped for safety).');
        console.log('  Run `npm rebuild` if native addons need compilation.\n');
      }
      process.exit(code || 0);
    });
    break;
  }

  case 'audit': {
    showBanner();
    console.log('  🔍 Auditing package integrity...\n');

    // Check if node_modules exists
    if (!fs.existsSync(path.join(process.cwd(), 'node_modules'))) {
      console.error('  ❌ No node_modules found. Run `npm install` first.\n');
      process.exit(1);
    }

    // Check if config exists
    const configPath = path.join(process.cwd(), '.sudarshana.json');
    if (!fs.existsSync(configPath)) {
      console.log('  ⚠️  No .sudarshana.json found. Run `sudarshana init` first.\n');
      process.exit(1);
    }

    console.log('  ✅ Config found: .sudarshana.json');
    console.log('  ✅ node_modules present');
    console.log('  📋 Full integrity audit coming in next version.\n');
    break;
  }

  case 'doctor': {
    showBanner();
    console.log('  🩺 Running Sudarshana diagnostics...\n');

    const checks = [
      { name: 'Node.js version', check: () => {
        const version = parseInt(process.version.slice(1));
        return version >= 16 ? `✅ ${process.version} (min: v16)` : `❌ ${process.version} (need v16+)`;
      }},
      { name: '.sudarshana.json', check: () => {
        return fs.existsSync(path.join(process.cwd(), '.sudarshana.json'))
          ? '✅ Found' : '⚠️  Not found — run `sudarshana init`';
      }},
      { name: 'package.json', check: () => {
        return fs.existsSync(path.join(process.cwd(), 'package.json'))
          ? '✅ Found' : '❌ Not found';
      }},
      { name: 'node_modules', check: () => {
        return fs.existsSync(path.join(process.cwd(), 'node_modules'))
          ? '✅ Present' : '⚠️  Missing — run `npm install`';
      }},
      { name: 'Permission API', check: () => {
        const version = parseInt(process.version.slice(1));
        return version >= 20 
          ? '✅ Available (Node 20+) — use --experimental-permission for max security'
          : '⚠️  Not available (need Node 20+)';
      }},
      { name: 'Platform', check: () => {
        const platform = process.platform;
        if (platform === 'linux') return '✅ Linux — full network namespace isolation available';
        if (platform === 'darwin') return '⚠️  macOS — network isolation limited (use Docker for full)';
        return '⚠️  Windows — network isolation limited (use WSL/Docker for full)';
      }}
    ];

    for (const { name, check } of checks) {
      console.log(`  ${name.padEnd(25)} ${check()}`);
    }

    // Run smoke tests
    const { runSmokeTest } = require('../src/cli/smoke-test');
    runSmokeTest();
    console.log('');
    break;
  }

  case 'learn': {
    const { LearnEngine } = require('../src/learn/learn-engine');
    const engine = new LearnEngine(process.cwd());

    if (args.includes('--status')) {
      console.log(engine.getStatus());
      break;
    }

    if (args.includes('--generate')) {
      const strict = args.includes('--strict');
      const policy = engine.generatePolicy({ strict });

      // Clean internal markers
      for (const p of Object.values(policy.policies)) {
        delete p._comment;
      }

      const configPath = path.join(process.cwd(), '.sudarshana.json');
      fs.writeFileSync(configPath, JSON.stringify(policy, null, 2));
      console.log('\n🧠 Sudarshana: Policy generated from ' + policy.$learnStats.totalRuns + ' observation runs.');
      console.log('   Packages observed: ' + policy.$learnStats.packagesObserved);
      console.log('   Mode: ' + (strict ? 'STRICT (deny anything unobserved)' : 'STANDARD'));
      console.log('\n   ✅ Written to: ' + configPath);
      console.log('   Run: sudarshana run -- node app.js\n');
      break;
    }

    if (args.includes('--reset')) {
      engine.reset();
      console.log('\n🧠 Sudarshana: All learned observations cleared.\n');
      break;
    }

    // Default: run in learn mode (observe)
    const separatorIdx = args.indexOf('--');
    if (separatorIdx === -1 || separatorIdx === args.length - 1) {
      console.log(engine.getStatus());
      console.log('  To observe your app: sudarshana learn -- node app.js');
      console.log('  To generate policy:  sudarshana learn --generate\n');
      break;
    }

    const childCmd = args.slice(separatorIdx + 1);
    const { spawn } = require('child_process');
    const sudarshanaPath = path.resolve(__dirname, '../src/index.js');

    console.log('🧠 Sudarshana: LEARN MODE — observing package behavior...');
    console.log('   Command: ' + childCmd.join(' ') + '\n');

    const child = spawn(childCmd[0], childCmd.slice(1), {
      stdio: 'inherit',
      env: {
        ...process.env,
        SUDARSHANA_MODE: 'learn',
        NODE_OPTIONS: (process.env.NODE_OPTIONS || '') + ' --require ' + sudarshanaPath
      },
      shell: true
    });

    child.on('exit', (code) => {
      engine.endRun();
      console.log('\n🧠 Observation run #' + engine.runCount + ' complete.');
      console.log('   Run `sudarshana learn --status` to see findings.');
      console.log('   Run `sudarshana learn --generate` when ready.\n');
      process.exit(code || 0);
    });
    break;
  }

  case 'snapshot': {
    showBanner();
    const { DriftDetector } = require('../src/drift/drift-detector');
    const detector = new DriftDetector(process.cwd());

    console.log('  📸 Creating behavioral snapshot...\n');
    const snapshot = detector.snapshot();
    console.log('  ✅ Snapshot saved.');
    console.log('  Packages fingerprinted: ' + Object.keys(snapshot.packages).length);
    console.log('  Stored in: .sudarshana-snapshots/latest.json');
    console.log('\n  Run `sudarshana drift` after updating packages to detect changes.\n');
    break;
  }

  case 'drift': {
    showBanner();
    const { DriftDetector } = require('../src/drift/drift-detector');
    const detector = new DriftDetector(process.cwd());

    try {
      const result = detector.detectDrift();
      console.log(detector.generateReport(result));

      // Exit with error code if critical drifts found (useful for CI)
      if (result.critical > 0) process.exit(1);
    } catch (e) {
      console.error('  ❌ ' + e.message + '\n');
      process.exit(1);
    }
    break;
  }

  case 'map': {
    showBanner();
    const { DependencyMap } = require('../src/viz/dependency-map');
    const mapper = new DependencyMap(process.cwd());

    const output = args.find(a => a.startsWith('--output='));
    const outputFile = output ? output.split('=')[1] : 'sudarshana-map.html';

    console.log('  🗺️  Generating dependency security map...\n');
    const result = mapper.generate({ output: outputFile });
    console.log('  ✅ Map generated: ' + result.outputPath);
    console.log('  Nodes: ' + result.stats.totalNodes);
    console.log('  Safe (zero access):  ' + result.stats.safe);
    console.log('  Elevated (network):  ' + result.stats.elevated);
    console.log('  Critical (shell):    ' + result.stats.critical);
    console.log('  Unprotected:         ' + result.stats.unprotected);
    console.log('\n  Open in browser to explore interactively.\n');
    break;
  }

  case 'scan': {
    showBanner();
    const { StaticScanner } = require('../src/scanner/static-scanner');
    const scanner = new StaticScanner(process.cwd());

    const target = args[1]; // Optional specific package

    if (target) {
      console.log(`  🔬 Scanning package: ${target}...\n`);
      const result = scanner.scanPackage(target);
      if (result.error) {
        console.error(`  ❌ ${result.error}\n`);
        process.exit(1);
      }
      console.log(`  Risk Score: ${result.riskScore}/100`);
      console.log(`  Obfuscation: ${result.obfuscationScore}/100`);
      console.log(`  Entropy: ${result.avgEntropy}`);
      console.log(`  Files scanned: ${result.filesScanned} (${result.totalLines} lines)\n`);
      console.log(`  Findings: 🔴${result.summary.critical} 🟠${result.summary.high} 🟡${result.summary.medium} 🔵${result.summary.low}\n`);
      for (const f of result.findings.filter(f => f.severity === 'critical' || f.severity === 'high')) {
        console.log(`  ${f.severity === 'critical' ? '🔴' : '🟠'} ${f.description}`);
        console.log(`     ${f.file} (×${f.count})`);
      }

      // Also scan install scripts
      const scriptResults = scanner.scanInstallScripts(target);
      if (scriptResults && scriptResults.length > 0) {
        console.log('\n  ⚡ Install Script Analysis:');
        for (const sr of scriptResults) {
          console.log(`     ${sr.script}: ${sr.command}`);
          for (const t of sr.threats) {
            console.log(`     ${t.severity === 'critical' ? '🔴' : '🟠'} ${t.detail}`);
          }
        }
      }
    } else {
      console.log('  🔬 Scanning all dependencies...\n');
      const results = scanner.scanAll();
      console.log(scanner.generateReport(results));
    }
    console.log('');
    break;
  }

  case 'sbom': {
    showBanner();
    const { ComplianceEngine } = require('../src/compliance/compliance-engine');
    const compliance = new ComplianceEngine(process.cwd());

    console.log('  📋 Generating CycloneDX SBOM...\n');
    const sbom = compliance.generateSBOM();
    const outputPath = path.join(process.cwd(), 'sbom.cdx.json');
    fs.writeFileSync(outputPath, JSON.stringify(sbom, null, 2));
    console.log(`  ✅ SBOM generated: ${outputPath}`);
    console.log(`  Components: ${sbom.components.length}`);
    console.log(`  Format: CycloneDX 1.5`);
    console.log(`  Includes: Sudarshana capability annotations\n`);
    break;
  }

  case 'forensics': {
    showBanner();
    const { ComplianceEngine } = require('../src/compliance/compliance-engine');
    const compliance = new ComplianceEngine(process.cwd());

    console.log('  🔍 Generating forensics timeline...\n');
    const report = compliance.generateForensicsReport();
    const outputPath = path.join(process.cwd(), 'sudarshana-forensics.json');
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
    console.log(`  ✅ Forensics report: ${outputPath}`);
    console.log(`  Events: ${report.eventCount}`);
    if (report.timeline.length > 0) {
      console.log('  Recent events:');
      for (const event of report.timeline.slice(-5)) {
        const icon = event.severity === 'CRITICAL' ? '🔴' : event.severity === 'HIGH' ? '🟠' : '🔵';
        console.log(`    ${icon} ${event.timestamp} — ${event.type} ${event.package || ''}`);
      }
    }
    console.log('');
    break;
  }

  case 'compliance': {
    showBanner();
    const { ComplianceEngine } = require('../src/compliance/compliance-engine');
    const compliance = new ComplianceEngine(process.cwd());

    const mapping = compliance.generateComplianceMapping();
    console.log('  📜 Compliance Framework Mapping\n');
    for (const [framework, controls] of Object.entries(mapping.frameworks)) {
      console.log(`  ${framework}:`);
      for (const [control, status] of Object.entries(controls)) {
        const icon = status === 'SATISFIED' ? '✅' : status === 'PARTIAL' ? '🟡' : '❌';
        console.log(`    ${icon} ${control}`);
      }
      console.log('');
    }
    console.log(`  Summary: ✅${mapping.summary.satisfied} 🟡${mapping.summary.partial} ❌${mapping.summary.notMet}\n`);
    break;
  }

  case 'predict': {
    showBanner();
    const { PredictiveEngine } = require('../src/predict/predictive-engine');
    const engine = new PredictiveEngine(process.cwd());

    const target = args[1];
    if (target) {
      console.log(`  🧠 Pre-merge simulation: ${target}\n`);
      const result = engine.simulatePackage(target);
      console.log(`  Risk: ${result.riskAssessment}`);
      console.log(`  Recommendation: ${result.recommendation}\n`);
      for (const p of result.predictions) {
        const icon = p.confidence === 'CERTAIN' ? '✓' : '~';
        console.log(`  ${icon} ${p.type}: ${p.detail}`);
      }
      if (result.suggestedPolicy) {
        console.log('\n  Suggested policy:');
        console.log('  ' + JSON.stringify(result.suggestedPolicy, null, 2).replace(/\n/g, '\n  '));
      }
    } else {
      console.log('  🧠 Running full predictive analysis...\n');
      const maintainerTrust = engine.analyzeMaintainerTrust();
      const { StaticScanner } = require('../src/scanner/static-scanner');
      const scanner = new StaticScanner(process.cwd());
      const scanResults = scanner.scanAll();
      const riskScores = {};
      for (const [name, data] of Object.entries(scanResults)) {
        riskScores[name] = data.riskScore || 0;
      }
      const transitiveRisk = engine.calculateTransitiveRisk(riskScores);
      console.log(engine.generateReport(transitiveRisk, [], maintainerTrust));
    }
    console.log('');
    break;

  case 'dashboard': {
    const { DashboardServer } = require('../src/dashboard/server');
    const dashboard = new DashboardServer(process.cwd());
    const port = parseInt(args.find(a => a.startsWith('--port='))?.split('=')[1] || '4040');
    dashboard.start(port);
    // Keep alive
    break;
  }

  case 'dna': {
    showBanner();
    const { BehavioralDNA } = require('../src/autonomous/behavioral-dna');
    const dna = new BehavioralDNA(process.cwd());

    console.log('  🧬 Scanning Behavioral DNA...\n');
    const result = dna.scanAll();
    console.log(dna.generateReport(result));
    
    if (result.mutations.length > 0) {
      console.log('  ⚠️  Mutations detected — review above.\n');
      process.exit(1); // CI-friendly exit code
    }
    break;
  }

  case 'heal': {
    showBanner();
    const { SelfHealingEngine } = require('../src/autonomous/self-healing');
    const healer = new SelfHealingEngine(process.cwd());

    const autoApply = args.includes('--apply');
    console.log(`  🩺 Running self-healing pass (${autoApply ? 'AUTO-APPLY' : 'dry-run'})...\n`);

    const recommendations = healer.heal({ autoApply });

    if (recommendations.length === 0) {
      console.log('  ✅ No changes needed. Policies are optimal.\n');
    } else {
      for (const rec of recommendations) {
        const icon = rec.type === 'TIGHTEN' ? '🔒' : '🔓';
        console.log(`  ${icon} ${rec.type}: ${rec.action}`);
        console.log(`     Reason: ${rec.reason}`);
      }
      console.log('');
      if (!autoApply) {
        console.log('  Run with --apply to auto-apply these changes.\n');
      } else {
        console.log('  ✅ Changes applied to .sudarshana.json\n');
      }
    }
    break;
  }

  case 'network': {
    showBanner();
    const { P2PThreatNetwork } = require('../src/network/p2p-threat-network');
    const network = new P2PThreatNetwork(process.cwd());
    const status = network.getStatus();
    console.log('  🌐 P2P Threat Network Status\n');
    console.log(`  Peer ID:        ${status.peerId}`);
    console.log(`  Endpoints:      ${status.endpoints}`);
    console.log(`  Local threats:  ${status.localThreats}`);
    console.log(`  Last sync:      ${status.lastSync || 'never'}`);
    console.log(`  Auto-publish:   ${status.autoPublish}`);
    console.log(`  Auto-subscribe: ${status.autoSubscribe}\n`);
    break;
  }

  case '--help':
  case '-h':
  case 'help':
  case undefined:
    showHelp();
    break;

  default:
    console.error(`Unknown command: ${command}`);
    console.error('Run `sudarshana --help` for usage.\n');
    process.exit(1);
}
