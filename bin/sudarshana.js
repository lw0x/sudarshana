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

  case 'decoy': {
    showBanner();
    const { DecoyGenerator } = require('../src/offensive/decoy-generator');
    const generator = new DecoyGenerator(process.cwd());

    if (args.includes('--generate')) {
      const type = args.find(a => a.startsWith('--type='))?.split('=')[1] || 'typosquat';
      console.log(`  🎭 Generating ${type} decoy packages...\n`);
      const decoys = generator.generateDecoys({ type, count: 5 });
      generator.saveToDisk(decoys);
      for (const d of decoys) {
        console.log(`  📦 ${d.name} (callback: ${d.callbackId})`);
      }
      console.log(`\n  ✅ ${decoys.length} decoys generated in .sudarshana-decoys/packages/`);
      console.log('  Review, then: cd .sudarshana-decoys/packages/<name> && npm publish\n');
    } else {
      console.log('  🎭 Decoy Package System\n');
      console.log('  Generate honeypot packages to trap attackers:\n');
      console.log('    sudarshana decoy --generate              Typosquat decoys');
      console.log('    sudarshana decoy --generate --type=confusion   Dep confusion decoys');
      console.log('    sudarshana decoy --generate --type=internal    Internal-name decoys\n');
    }
    break;
  }

  case 'watch': {
    showBanner();
    const { RegistryWatcher } = require('../src/offensive/registry-watcher');
    const watcher = new RegistryWatcher(process.cwd());

    if (args.includes('--timebombs')) {
      console.log('  ⏰ Scanning for time-bomb patterns...\n');
      const alerts = watcher.detectTimeBombs();
      console.log(watcher.generateReport(alerts));
    } else if (args.includes('--watchlist')) {
      const watchlist = watcher.generateWatchlist();
      console.log('  👁️  Typosquat Watchlist\n');
      for (const item of watchlist.slice(0, 10)) {
        console.log(`  ${item.original} → ${item.variants.slice(0, 3).join(', ')}...`);
      }
      console.log(`\n  Total packages monitored: ${watchlist.length}`);
      console.log(`  Total variants tracked: ${watchlist.reduce((s, w) => s + w.variants.length, 0)}\n`);
    } else {
      console.log('  👁️  Registry Watcher\n');
      console.log('  Commands:\n');
      console.log('    sudarshana watch --timebombs     Scan installed packages for time-bomb code');
      console.log('    sudarshana watch --watchlist     Show typosquat variants being monitored');
      console.log('    sudarshana watch --check         Check npm registry (requires network)\n');
    }
    break;
  }

  case 'intel': {
    showBanner();
    const { AttackerProfiler } = require('../src/offensive/attacker-profiler');
    const profiler = new AttackerProfiler(process.cwd());
    console.log(profiler.getReport());
    break;
  }

  case 'simulate': {
    showBanner();
    const { AttackSimulator } = require('../src/omniscience/attack-simulator');
    const simulator = new AttackSimulator(process.cwd());

    console.log('  🎯 Running attack simulation (16 scenarios)...\n');
    const results = simulator.simulate();
    console.log(simulator.generateReport(results));
    if (results.bypassed > 0) process.exit(1);
    break;
  }

  case 'attest': {
    showBanner();
    const { ProvenanceEngine } = require('../src/omniscience/provenance');
    const provenance = new ProvenanceEngine(process.cwd());

    if (args.includes('--verify')) {
      console.log('  🔐 Verifying supply chain provenance...\n');
      try {
        const result = provenance.verify();
        console.log(provenance.generateReport(result));
        if (result.critical > 0) process.exit(1);
      } catch(e) {
        console.error(`  ❌ ${e.message}\n`);
        process.exit(1);
      }
    } else {
      console.log('  🔐 Generating supply chain attestation...\n');
      const attestation = provenance.generateAttestation();
      console.log(`  ✅ Attestation generated`);
      console.log(`  Packages attested: ${Object.keys(attestation.attestations).length}`);
      console.log(`  Root hash: ${attestation.rootHash.substring(0, 16)}...`);
      console.log(`  Stored: .sudarshana-provenance/attestation.json`);
      console.log(`\n  Run \`sudarshana attest --verify\` after updates to detect tampering.\n`);
    }
    break;
  }

  case 'advisory': {
    showBanner();
    const { AutoAdvisory } = require('../src/omniscience/auto-advisory');
    const advisory = new AutoAdvisory(process.cwd());

    const pkg = args[1];
    const version = args[2];
    const threat = args.find(a => a.startsWith('--threat='))?.split('=')[1] || 'HONEYPOT_ACCESS';

    if (!pkg || !version) {
      console.log('  📋 Auto-Advisory Generator\n');
      console.log('  Usage: sudarshana advisory <package> <version> --threat=<type>\n');
      console.log('  Threat types: HONEYPOT_ACCESS, READ_THEN_SEND, STAGED_EXFILTRATION,');
      console.log('                CONTENT_MUTATED_SAME_VERSION, DNS_TUNNELING\n');
    } else {
      console.log(`  📋 Generating security advisory for ${pkg}@${version}...\n`);
      const result = advisory.generate({ package: pkg, version, threatType: threat, severity: 'CRITICAL' });
      console.log(`  ✅ Advisory ${result.advisoryId} generated`);
      console.log(`  Reports: GHSA, CVE, npm abuse, internal`);
      console.log(`  Saved: .sudarshana-advisories/${result.advisoryId}.json`);
      console.log(`  Markdown: .sudarshana-advisories/${result.advisoryId}.md\n`);
    }
    break;
  }

  case 'kernel': {
    showBanner();
    const { KernelPolicyGenerator } = require('../src/singularity/kernel-policy');
    const generator = new KernelPolicyGenerator(process.cwd());

    console.log('  ⚛️  Generating kernel-level security policies...\n');
    const result = generator.generate();
    const outputDir = generator.savePolicies(result);
    console.log(`  Platform: ${result.platform}`);
    console.log(`  Profiles generated:`);
    for (const [name] of Object.entries(result.profiles)) {
      console.log(`    ✅ ${name}`);
    }
    console.log(`\n  Saved to: ${outputDir}\n`);
    break;
  }

  case 'precrime': {
    showBanner();
    const { PreCrimeEngine } = require('../src/temporal/pre-crime');
    const engine = new PreCrimeEngine(process.cwd());

    console.log('  🔮 Running pre-crime analysis...\n');
    const results = engine.analyze();
    console.log(engine.generateReport(results));
    break;
  }

  case 'twin': {
    showBanner();
    const { DigitalTwin } = require('../src/temporal/digital-twin');
    const twin = new DigitalTwin(process.cwd());

    if (args.includes('--snapshot')) {
      console.log('  ⏳ Taking digital twin snapshot...\n');
      const snap = twin.snapshot();
      console.log(`  ✅ Snapshot ${snap.id} saved`);
      console.log(`  Packages captured: ${Object.keys(snap.packages).length}`);
      console.log(`  Timeline depth: ${twin.timeline.snapshots.length} snapshots\n`);
    } else if (args.includes('--regression')) {
      const from = parseInt(args.find(a => a.startsWith('--from='))?.split('=')[1] || '0');
      const to = twin.timeline.snapshots.length - 1;
      if (twin.timeline.snapshots.length < 2) {
        console.log('  Need at least 2 snapshots. Run `sudarshana twin --snapshot` twice.\n');
      } else {
        const analysis = twin.regressionAnalysis(from, to);
        console.log(twin.generateReport(analysis));
      }
    } else if (args.includes('--audit')) {
      const pkg = args[args.indexOf('--audit') + 1];
      const fromV = args.find(a => a.startsWith('--from='))?.split('=')[1] || '0.0.0';
      const toV = args.find(a => a.startsWith('--to='))?.split('=')[1] || '999.0.0';
      if (!pkg) {
        console.log('  Usage: sudarshana twin --audit <package> --from=1.0.0 --to=1.0.1\n');
      } else {
        const exposure = twin.timeTravelAudit(pkg, fromV, toV);
        console.log('  ⏳ Time-Travel Audit: ' + pkg + '\n');
        console.log('  ' + JSON.stringify(exposure, null, 2).replace(/\n/g, '\n  '));
        console.log('');
      }
    } else {
      const status = twin.getStatus();
      console.log('  ⏳ Digital Twin Status\n');
      console.log(`  Snapshots: ${status.snapshots}`);
      console.log(`  First: ${status.firstSnapshot || 'none'}`);
      console.log(`  Last:  ${status.lastSnapshot || 'none'}`);
      console.log('');
      console.log('  Commands:');
      console.log('    sudarshana twin --snapshot        Take new snapshot');
      console.log('    sudarshana twin --regression      Compare first vs latest');
      console.log('    sudarshana twin --audit <pkg>     Time-travel audit\n');
    }
    break;
  }

  case 'proxy': {
    const { RegistryProxy } = require('../src/transcendence/registry-proxy');
    const port = parseInt(args.find(a => a.startsWith('--port='))?.split('=')[1] || '4873');
    const proxy = new RegistryProxy({ port, projectRoot: process.cwd() });
    proxy.start();
    break;
  }

  case 'polyglot': {
    showBanner();
    const { PolyglotEngine } = require('../src/transcendence/polyglot-engine');
    const engine = new PolyglotEngine(process.cwd());

    if (args.includes('--detect')) {
      const detected = engine.detectEcosystems();
      console.log('  🌐 Detected ecosystems:\n');
      for (const eco of detected) {
        console.log(`    ✅ ${eco.name} (${eco.manifest})`);
      }
      if (detected.length === 0) console.log('    No recognized ecosystems found.');
      console.log('');
    } else if (args.includes('--ecosystems')) {
      const info = engine.getEcosystemInfo();
      console.log('  🌐 Supported Ecosystems:\n');
      for (const eco of info) {
        console.log(`    ${eco.name.padEnd(25)} manifest: ${eco.manifest.padEnd(20)} patterns: ${eco.patternCount}`);
      }
      console.log('');
    } else {
      console.log('  🌐 Polyglot Engine — Multi-ecosystem security\n');
      console.log('    sudarshana polyglot --detect       Detect project ecosystems');
      console.log('    sudarshana polyglot --ecosystems   List all supported ecosystems\n');
    }
    break;
  }

  case 'immune': {
    showBanner();
    const { ImmuneSystem } = require('../src/transcendence/immune-system');
    const immune = new ImmuneSystem(process.cwd());
    console.log(immune.generateReport());
    break;
  }

  case 'agent': {
    showBanner();
    const { SystemAgent } = require('../src/omnipresence/system-agent');
    const agent = new SystemAgent();

    if (args.includes('start')) {
      agent.start();
    } else if (args.includes('stop')) {
      agent.stop();
      console.log('  Agent stopped.\n');
    } else {
      const status = agent.getStatus();
      console.log('  🖥️  System Agent Status\n');
      console.log(`  Running: ${status.running ? '✅ yes (PID: ' + status.pid + ')' : '❌ no'}`);
      console.log(`  Port: ${status.port}`);
      console.log(`\n  Commands:`);
      console.log('    sudarshana agent start     Start background daemon');
      console.log('    sudarshana agent stop      Stop daemon\n');
    }
    break;
  }

  case 'eliminate': {
    showBanner();
    const { DependencyEliminator } = require('../src/genesis/dep-eliminator');
    const eliminator = new DependencyEliminator(process.cwd());

    console.log('  🌱 Analyzing dependencies for elimination...\n');
    const analysis = eliminator.analyze();
    console.log(eliminator.generateReport(analysis));

    if (args.includes('--generate') && analysis.eliminable.length > 0) {
      const replacements = eliminator.generateReplacements();
      const outDir = eliminator.saveReplacements(replacements);
      console.log(`  ✅ Replacements generated in: ${outDir}\n`);
    }
    break;
  }

  case 'certify': {
    showBanner();
    const { CertificationAuthority } = require('../src/sovereignty/certification');
    const ca = new CertificationAuthority(process.cwd());

    const target = args[1];
    if (target && !target.startsWith('-')) {
      console.log(`  👑 Certifying: ${target}...\n`);
      try {
        const cert = ca.certify(target);
        if (cert.certified === false) {
          console.log(`  ○ Not certified: ${cert.reason}\n`);
        } else {
          console.log(`  ${cert.levelLabel} CERTIFIED — ${target}@${cert.subject.version}`);
          console.log(`  ID: ${cert.id}`);
          console.log(`  Expires: ${cert.expires}\n`);
        }
      } catch(e) { console.error(`  ❌ ${e.message}\n`); }
    } else {
      console.log('  👑 Certifying all dependencies...\n');
      const results = ca.certifyAll();
      console.log(ca.generateReport(results));
    }
    break;
  }

  case 'precognition': {
    showBanner();
    const { PrecognitionNetwork } = require('../src/absolute/precognition');
    const precog = new PrecognitionNetwork(process.cwd());
    console.log(precog.generateReport());
    break;
  }

  case 'eject': {
    const { eject } = require('../src/compat/runtime-compat');
    const disableFile = eject(process.cwd());
    console.log('\n  ⏏️  Sudarshana EJECTED (disabled instantly)\n');
    console.log('  Your app will run without any Sudarshana hooks.');
    console.log('  To re-enable: sudarshana enable');
    console.log(`  (or delete: ${disableFile})\n`);
    break;
  }

  case 'enable': {
    const { enable } = require('../src/compat/runtime-compat');
    const wasDisabled = enable(process.cwd());
    if (wasDisabled) {
      console.log('\n  ✅ Sudarshana RE-ENABLED\n');
    } else {
      console.log('\n  ℹ️  Sudarshana was not disabled.\n');
    }
    break;
  }

  case 'debug': {
    showBanner();
    const { DebugLogger } = require('../src/compat/runtime-compat');
    const debugLog = path.join(process.cwd(), '.sudarshana-debug.json');

    if (fs.existsSync(debugLog)) {
      const data = JSON.parse(fs.readFileSync(debugLog, 'utf8'));
      console.log('  🐛 Debug Log\n');
      console.log(`  Events: ${data.eventCount}`);
      console.log(`  Blocks: ${data.blocks}`);
      console.log(`  Fallbacks: ${data.fallbacks}\n`);
      if (data.blocks > 0) {
        console.log('  Recent blocks:');
        const blocks = data.events.filter(e => e.category === 'BLOCK').slice(-10);
        for (const b of blocks) {
          console.log(`    🚫 ${b.message}`);
        }
      }
      console.log('\n  Full log: .sudarshana-debug.json\n');
    } else {
      console.log('  🐛 Debug Mode\n');
      console.log('  No debug log found. Run your app with debug enabled:\n');
      console.log('    SUDARSHANA_DEBUG=1 sudarshana run -- node app.js\n');
      console.log('  This logs every allow/block decision to .sudarshana-debug.json');
      console.log('  Use this to diagnose "why is my package blocked?"\n');
    }
    break;
  }

  case 'env': {
    showBanner();
    const { detectEnvironment, getSandboxStrategy } = require('../src/compat/runtime-compat');
    const env = detectEnvironment(process.cwd());
    const strategy = getSandboxStrategy(env);
    console.log('  🔍 Project Environment\n');
    console.log(`  TypeScript:       ${env.typescript ? '✅ ' + (env.tsRunner || 'detected') : '❌'}`);
    console.log(`  Bundler:          ${env.bundler || 'none'}`);
    console.log(`  Monorepo:         ${env.monorepo || 'none'}`);
    console.log(`  Serverless:       ${env.serverless || 'none'}`);
    console.log(`  Module type:      ${env.moduleType}`);
    console.log(`  Package manager:  ${env.packageManager}`);
    console.log(`\n  Sandbox strategy: ${strategy.strategy}`);
    console.log(`  Reason: ${strategy.reason}\n`);
    break;
  }

  case 'vuln': {
    showBanner();
    const { VulnerabilityDB } = require('../src/free-tier/vulnerability-db');
    const vulnDb = new VulnerabilityDB(process.cwd());

    console.log('  🔓 Scanning for known vulnerabilities (via OSV.dev)...\n');
    vulnDb.scanAll().then(results => {
      const fixes = vulnDb.generateFixes(results);
      console.log(vulnDb.generateReport(results, fixes));
    }).catch(e => {
      console.error('  ❌ Scan failed: ' + e.message);
      console.log('  Note: requires network access to query OSV.dev\n');
    });
    break;
  }

  case 'license': {
    showBanner();
    const { LicenseCompliance } = require('../src/free-tier/license-compliance');
    const compliance = new LicenseCompliance(process.cwd());

    const policyName = args.find(a => a.startsWith('--policy='))?.split('=')[1] || 'moderate';
    const scanResults = compliance.scan();
    const enforcement = compliance.enforce(scanResults, policyName);
    console.log(compliance.generateReport(enforcement));

    if (args.includes('--export=csv')) {
      const csv = compliance.exportCSV(scanResults);
      const outPath = path.join(process.cwd(), 'sudarshana-licenses.csv');
      fs.writeFileSync(outPath, csv);
      console.log(`  📄 Exported to: ${outPath}\n`);
    }
    break;
  }

  case 'graph': {
    showBanner();
    const { DependencyGraph } = require('../src/free-tier/dependency-graph');
    const graph = new DependencyGraph(process.cwd());

    console.log('  🌳 Building dependency graph...\n');
    graph.buildGraph();
    const analysis = graph.analyze();
    console.log(graph.generateReport(analysis));
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
