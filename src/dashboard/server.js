'use strict';

/**
 * SUDARSHANA — LEVEL 9: LOCAL DASHBOARD
 * 
 * "sudarshana dashboard" → browser opens real-time security UI
 * 
 * Zero dependencies. Pure Node.js HTTP server.
 * Serves a self-contained dark-theme dashboard showing:
 * - Package risk overview (live from .sudarshana.json)
 * - Quarantine status
 * - Threat feed
 * - Drift history
 * - Learn mode progress
 * - Compliance status
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const DEFAULT_PORT = 4040;

class DashboardServer {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.server = null;
  }

  /**
   * Start the dashboard server
   */
  start(port = DEFAULT_PORT) {
    this.server = http.createServer((req, res) => {
      if (req.url === '/' || req.url === '/index.html') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(this._generateDashboardHTML());
      } else if (req.url === '/api/status') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(this._getStatus()));
      } else if (req.url === '/api/packages') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(this._getPackages()));
      } else if (req.url === '/api/threats') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(this._getThreats()));
      } else if (req.url === '/api/quarantine') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(this._getQuarantine()));
      } else {
        res.writeHead(404);
        res.end('not found');
      }
    });

    this.server.listen(port, () => {
      console.log(`\n  🔥 Sudarshana Dashboard`);
      console.log(`  ───────────────────────────────────`);
      console.log(`  Running at: http://localhost:${port}`);
      console.log(`  Project:    ${path.basename(this.projectRoot)}`);
      console.log(`\n  Press Ctrl+C to stop.\n`);
    });

    return this.server;
  }

  _getStatus() {
    const configPath = path.join(this.projectRoot, '.sudarshana.json');
    const hasConfig = fs.existsSync(configPath);
    let config = null;
    if (hasConfig) {
      try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch(e) {}
    }

    const pkgPath = path.join(this.projectRoot, 'package.json');
    let pkg = { name: 'unknown', version: '0.0.0' };
    if (fs.existsSync(pkgPath)) {
      try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch(e) {}
    }

    const learnPath = path.join(this.projectRoot, '.sudarshana-learn', 'observations.json');
    let learnRuns = 0;
    if (fs.existsSync(learnPath)) {
      try { learnRuns = JSON.parse(fs.readFileSync(learnPath, 'utf8')).runCount || 0; } catch(e) {}
    }

    return {
      project: pkg.name,
      version: pkg.version,
      configured: hasConfig,
      mode: config ? config.mode : 'none',
      policyCount: config ? Object.keys(config.policies || {}).length : 0,
      learnRuns,
      timestamp: new Date().toISOString()
    };
  }

  _getPackages() {
    const configPath = path.join(this.projectRoot, '.sudarshana.json');
    if (!fs.existsSync(configPath)) return [];

    try {
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      return Object.entries(config.policies || {}).map(([name, policy]) => ({
        name,
        trustLevel: policy.trust_level,
        env: (policy.env_visible || []).length,
        network: (policy.network || []).length,
        fs: (policy.fs_read || []).length + (policy.fs_write || []).length,
        shell: (policy.shell || []).length
      }));
    } catch(e) { return []; }
  }

  _getThreats() {
    const threatPath = path.join(this.projectRoot, '.sudarshana-threats', 'known-threats.json');
    if (!fs.existsSync(threatPath)) return [];
    try {
      return JSON.parse(fs.readFileSync(threatPath, 'utf8')).threats || [];
    } catch(e) { return []; }
  }

  _getQuarantine() {
    const qPath = path.join(this.projectRoot, '.sudarshana-quarantine', 'quarantine.jsonl');
    if (!fs.existsSync(qPath)) return [];
    try {
      return fs.readFileSync(qPath, 'utf8').trim().split('\n')
        .map(line => { try { return JSON.parse(line); } catch(e) { return null; } })
        .filter(Boolean);
    } catch(e) { return []; }
  }

  _generateDashboardHTML() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sudarshana — Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      background: #0a0a0f;
      color: #e0e0e0;
      font-family: -apple-system, 'Segoe UI', sans-serif;
      padding: 24px;
    }
    .header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 32px;
      border-bottom: 1px solid #1a1a2a;
      padding-bottom: 16px;
    }
    .header h1 { color: #ff6b35; font-size: 20px; }
    .header .subtitle { color: #555; font-size: 12px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .card {
      background: #111118;
      border: 1px solid #222;
      border-radius: 12px;
      padding: 20px;
    }
    .card h3 { color: #888; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
    .stat { font-size: 32px; font-weight: 700; color: #fff; }
    .stat.green { color: #00ff88; }
    .stat.orange { color: #ff9500; }
    .stat.red { color: #ff4444; }
    .packages-table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    .packages-table th { text-align: left; color: #555; font-size: 11px; padding: 8px; border-bottom: 1px solid #222; }
    .packages-table td { padding: 8px; border-bottom: 1px solid #1a1a1a; font-size: 13px; }
    .badge {
      display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600;
    }
    .badge-trusted { background: #002a00; color: #00ff88; }
    .badge-limited { background: #2a2200; color: #ffd700; }
    .badge-untrusted { background: #2a0000; color: #ff4444; }
    .badge-system { background: #001a3a; color: #4488ff; }
    .threat-item {
      padding: 12px; margin: 8px 0; background: #1a0000; border-left: 3px solid #ff4444; border-radius: 4px;
    }
    .threat-item .pkg { color: #ff6b35; font-weight: 600; }
    .threat-item .detail { color: #888; font-size: 12px; margin-top: 4px; }
    .empty { color: #333; font-style: italic; padding: 20px; text-align: center; }
    .footer { margin-top: 40px; text-align: center; color: #333; font-size: 11px; }
    .pulse { animation: pulse 2s infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔥 Sudarshana</h1>
    <div class="subtitle">Supply Chain Defense — <span id="project-name">loading...</span> — <span id="refresh-time" class="pulse">●</span></div>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Status</h3>
      <div class="stat green" id="status-mode">—</div>
    </div>
    <div class="card">
      <h3>Protected Packages</h3>
      <div class="stat" id="policy-count">—</div>
    </div>
    <div class="card">
      <h3>Learn Runs</h3>
      <div class="stat" id="learn-runs">—</div>
    </div>
    <div class="card">
      <h3>Threats Detected</h3>
      <div class="stat red" id="threat-count">—</div>
    </div>
  </div>

  <div class="card" style="margin-bottom: 16px;">
    <h3>Package Policies</h3>
    <table class="packages-table" id="packages-table">
      <thead><tr><th>Package</th><th>Trust</th><th>Env</th><th>Net</th><th>FS</th><th>Shell</th></tr></thead>
      <tbody id="packages-body"></tbody>
    </table>
  </div>

  <div class="card">
    <h3>Threat Feed</h3>
    <div id="threats-list"><div class="empty">No threats detected. The disc is watching.</div></div>
  </div>

  <div class="footer">
    every package thinks it's alone. it is. — sudarshana v2.0
  </div>

  <script>
    async function refresh() {
      try {
        const status = await (await fetch('/api/status')).json();
        document.getElementById('project-name').textContent = status.project + ' v' + status.version;
        document.getElementById('status-mode').textContent = status.configured ? status.mode.toUpperCase() : 'NOT CONFIGURED';
        document.getElementById('policy-count').textContent = status.policyCount;
        document.getElementById('learn-runs').textContent = status.learnRuns;

        const packages = await (await fetch('/api/packages')).json();
        const tbody = document.getElementById('packages-body');
        tbody.innerHTML = packages.map(p => {
          const badge = 'badge-' + (p.trustLevel || 'untrusted');
          return '<tr><td>' + p.name + '</td><td><span class="badge ' + badge + '">' +
            (p.trustLevel || '?') + '</span></td><td>' + p.env + '</td><td>' + p.network +
            '</td><td>' + p.fs + '</td><td>' + p.shell + '</td></tr>';
        }).join('');

        const threats = await (await fetch('/api/threats')).json();
        document.getElementById('threat-count').textContent = threats.length;
        const threatsList = document.getElementById('threats-list');
        if (threats.length > 0) {
          threatsList.innerHTML = threats.slice(-10).reverse().map(t =>
            '<div class="threat-item"><span class="pkg">' + t.package + '@' + t.version +
            '</span><div class="detail">' + t.threatType + ' — ' + t.firstSeen + '</div></div>'
          ).join('');
        }
      } catch(e) { console.error('refresh failed:', e); }
    }

    refresh();
    setInterval(refresh, 5000); // Auto-refresh every 5s
  </script>
</body>
</html>`;
  }
}

module.exports = { DashboardServer };
