'use strict';

/**
 * SUDARSHANA — DEPENDENCY VISUALIZATION
 * 
 * "One picture. Your entire attack surface."
 * 
 * Generates an interactive HTML page showing:
 * - Every package as a node
 * - Color-coded by risk (green=pure, yellow=network, red=shell)
 * - Connections showing dependency chains
 * - Click a package → see exactly what it can access
 * 
 * Usage:
 *   sudarshana map                         (generate interactive HTML)
 *   sudarshana map --output report.html    (custom output path)
 */

const fs = require('fs');
const path = require('path');

class DependencyMap {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
  }

  /**
   * Generate the interactive HTML dependency map
   */
  generate(options = {}) {
    const { output = 'sudarshana-map.html' } = options;
    const nodeModulesPath = path.join(this.projectRoot, 'node_modules');

    if (!fs.existsSync(path.join(this.projectRoot, 'package.json'))) {
      throw new Error('No package.json found.');
    }

    // Load config if exists
    let config = { policies: {} };
    const configPath = path.join(this.projectRoot, '.sudarshana.json');
    if (fs.existsSync(configPath)) {
      config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }

    // Get dependencies
    const projectPkg = JSON.parse(
      fs.readFileSync(path.join(this.projectRoot, 'package.json'), 'utf8')
    );

    const deps = Object.keys(projectPkg.dependencies || {});
    const devDeps = Object.keys(projectPkg.devDependencies || {});

    // Build node data
    const nodes = [];
    const edges = [];

    // Add project node
    nodes.push({
      id: '_app_',
      label: projectPkg.name || 'Your App',
      group: 'app',
      risk: 'system',
      capabilities: ['everything']
    });

    // Analyze each dependency
    for (const dep of [...deps, ...devDeps]) {
      const policy = config.policies[dep] || null;
      const depPath = path.join(nodeModulesPath, dep);

      let capabilities = [];
      let risk = 'unknown';

      if (policy) {
        // Use policy to determine capabilities
        if (policy.network && policy.network.length > 0) capabilities.push('network');
        if (policy.env_visible && policy.env_visible.length > 0) capabilities.push('env');
        if (policy.fs_read && policy.fs_read.length > 0) capabilities.push('fs_read');
        if (policy.fs_write && policy.fs_write.length > 0) capabilities.push('fs_write');
        if (policy.shell && policy.shell.length > 0) capabilities.push('shell');

        if (capabilities.length === 0) risk = 'safe';
        else if (capabilities.includes('shell')) risk = 'critical';
        else if (capabilities.includes('network')) risk = 'elevated';
        else risk = 'moderate';
      } else if (fs.existsSync(depPath)) {
        // No policy — scan the package
        risk = 'unprotected';
        capabilities.push('unscanned');
      }

      nodes.push({
        id: dep,
        label: dep,
        group: devDeps.includes(dep) ? 'dev' : 'prod',
        risk,
        capabilities,
        policy: policy ? 'configured' : 'none'
      });

      edges.push({ from: '_app_', to: dep });

      // Get transitive deps (1 level deep)
      if (fs.existsSync(depPath)) {
        try {
          const depPkg = JSON.parse(fs.readFileSync(path.join(depPath, 'package.json'), 'utf8'));
          const transitiveDeps = Object.keys(depPkg.dependencies || {}).slice(0, 5); // limit
          for (const td of transitiveDeps) {
            if (!nodes.find(n => n.id === td)) {
              nodes.push({ id: td, label: td, group: 'transitive', risk: 'unknown', capabilities: [] });
            }
            edges.push({ from: dep, to: td });
          }
        } catch (e) { /* skip */ }
      }
    }

    // Generate HTML
    const html = this._generateHTML(nodes, edges, projectPkg.name || 'project');
    const outputPath = path.join(this.projectRoot, output);
    fs.writeFileSync(outputPath, html);

    return {
      outputPath,
      stats: {
        totalNodes: nodes.length,
        safe: nodes.filter(n => n.risk === 'safe').length,
        elevated: nodes.filter(n => n.risk === 'elevated').length,
        critical: nodes.filter(n => n.risk === 'critical').length,
        unprotected: nodes.filter(n => n.risk === 'unprotected').length
      }
    };
  }

  /**
   * Generate self-contained HTML with embedded visualization
   */
  _generateHTML(nodes, edges, projectName) {
    const nodesJson = JSON.stringify(nodes);
    const edgesJson = JSON.stringify(edges);

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sudarshana — Dependency Security Map</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      background: #0a0a0f;
      color: #e0e0e0;
      font-family: 'JetBrains Mono', 'Fira Code', monospace;
      overflow: hidden;
    }
    #header {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 100;
      padding: 16px 24px;
      background: linear-gradient(180deg, #0a0a0f 0%, transparent 100%);
    }
    #header h1 {
      font-size: 14px;
      color: #ff6b35;
      letter-spacing: 2px;
      text-transform: uppercase;
    }
    #header .subtitle {
      font-size: 11px;
      color: #555;
      margin-top: 4px;
    }
    #canvas {
      width: 100vw;
      height: 100vh;
    }
    #info-panel {
      position: fixed;
      bottom: 20px;
      right: 20px;
      width: 320px;
      background: #111118;
      border: 1px solid #222;
      border-radius: 8px;
      padding: 16px;
      font-size: 12px;
      display: none;
      z-index: 100;
    }
    #info-panel.active { display: block; }
    #info-panel h3 {
      color: #ff6b35;
      margin-bottom: 8px;
      font-size: 14px;
    }
    #info-panel .field {
      margin-bottom: 6px;
      display: flex;
      justify-content: space-between;
    }
    #info-panel .field .label { color: #666; }
    #info-panel .field .value { color: #fff; }
    .cap-tag {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 3px;
      font-size: 10px;
      margin: 2px;
    }
    .cap-network { background: #3a2200; color: #ff9500; }
    .cap-env { background: #2a2200; color: #ffd700; }
    .cap-fs_read { background: #002a00; color: #00ff88; }
    .cap-fs_write { background: #2a0000; color: #ff4444; }
    .cap-shell { background: #3a0000; color: #ff0000; }
    .cap-unscanned { background: #1a1a2a; color: #888; }
    #stats {
      position: fixed;
      top: 60px;
      right: 20px;
      font-size: 11px;
      color: #555;
      text-align: right;
      z-index: 100;
    }
    #stats .stat { margin-bottom: 4px; }
    .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
    .dot-safe { background: #00ff88; }
    .dot-elevated { background: #ff9500; }
    .dot-critical { background: #ff0000; }
    .dot-unprotected { background: #444; }
    .dot-unknown { background: #333; }
    #legend {
      position: fixed;
      bottom: 20px;
      left: 20px;
      font-size: 11px;
      color: #555;
      z-index: 100;
    }
    #legend div { margin-bottom: 4px; }
  </style>
</head>
<body>
  <div id="header">
    <h1>🔥 Sudarshana</h1>
    <div class="subtitle">Dependency Security Map — ${projectName} — ${new Date().toISOString().split('T')[0]}</div>
  </div>

  <div id="stats">
    <div class="stat"><span class="dot dot-safe"></span>Safe (zero access)</div>
    <div class="stat"><span class="dot dot-elevated"></span>Elevated (network)</div>
    <div class="stat"><span class="dot dot-critical"></span>Critical (shell)</div>
    <div class="stat"><span class="dot dot-unprotected"></span>No policy</div>
  </div>

  <canvas id="canvas"></canvas>

  <div id="info-panel">
    <h3 id="panel-title">Package</h3>
    <div id="panel-content"></div>
  </div>

  <div id="legend">
    <div>Click a node to inspect</div>
    <div>Scroll to zoom • Drag to pan</div>
    <div style="margin-top: 8px; color: #ff6b35;">every package thinks it's alone. it is.</div>
  </div>

  <script>
    const nodes = ${nodesJson};
    const edges = ${edgesJson};

    const canvas = document.getElementById('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const riskColors = {
      system: '#ff6b35',
      safe: '#00ff88',
      moderate: '#ffd700',
      elevated: '#ff9500',
      critical: '#ff0000',
      unprotected: '#444444',
      unknown: '#333333'
    };

    // Force-directed layout simulation
    const positions = {};
    const velocities = {};

    // Initialize positions in a circle
    nodes.forEach((node, i) => {
      const angle = (2 * Math.PI * i) / nodes.length;
      const radius = Math.min(canvas.width, canvas.height) * 0.3;
      positions[node.id] = {
        x: canvas.width / 2 + Math.cos(angle) * radius * (node.id === '_app_' ? 0 : 1),
        y: canvas.height / 2 + Math.sin(angle) * radius * (node.id === '_app_' ? 0 : 1)
      };
      velocities[node.id] = { x: 0, y: 0 };
    });

    // Center the app node
    positions['_app_'] = { x: canvas.width / 2, y: canvas.height / 2 };

    let offsetX = 0, offsetY = 0, scale = 1;
    let selectedNode = null;
    let animating = true;
    let frame = 0;

    function simulate() {
      const damping = 0.9;
      const repulsion = 5000;
      const attraction = 0.01;
      const idealLength = 150;

      // Repulsion between all nodes
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = positions[nodes[i].id];
          const b = positions[nodes[j].id];
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
          const force = repulsion / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          velocities[nodes[i].id].x -= fx;
          velocities[nodes[i].id].y -= fy;
          velocities[nodes[j].id].x += fx;
          velocities[nodes[j].id].y += fy;
        }
      }

      // Attraction along edges
      for (const edge of edges) {
        const a = positions[edge.from];
        const b = positions[edge.to];
        if (!a || !b) continue;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const force = (dist - idealLength) * attraction;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        velocities[edge.from].x += fx;
        velocities[edge.from].y += fy;
        velocities[edge.to].x -= fx;
        velocities[edge.to].y -= fy;
      }

      // Apply velocities
      for (const node of nodes) {
        if (node.id === '_app_') continue; // Keep app centered
        velocities[node.id].x *= damping;
        velocities[node.id].y *= damping;
        positions[node.id].x += velocities[node.id].x;
        positions[node.id].y += velocities[node.id].y;
      }
    }

    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.save();
      ctx.translate(offsetX, offsetY);
      ctx.scale(scale, scale);

      // Draw edges
      ctx.strokeStyle = '#1a1a2a';
      ctx.lineWidth = 0.5;
      for (const edge of edges) {
        const from = positions[edge.from];
        const to = positions[edge.to];
        if (!from || !to) continue;
        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.stroke();
      }

      // Draw nodes
      for (const node of nodes) {
        const pos = positions[node.id];
        if (!pos) continue;
        const color = riskColors[node.risk] || '#333';
        const radius = node.id === '_app_' ? 20 : (node.group === 'transitive' ? 4 : 8);

        // Glow effect for critical
        if (node.risk === 'critical') {
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, radius + 4, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(255, 0, 0, 0.15)';
          ctx.fill();
        }

        ctx.beginPath();
        ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();

        // Selected highlight
        if (selectedNode === node.id) {
          ctx.strokeStyle = '#fff';
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        // Label
        if (radius > 4) {
          ctx.fillStyle = '#888';
          ctx.font = '9px monospace';
          ctx.textAlign = 'center';
          ctx.fillText(node.label, pos.x, pos.y + radius + 12);
        }
      }

      ctx.restore();
      frame++;
      if (frame < 300) simulate(); // Stop simulation after settling
      if (animating) requestAnimationFrame(draw);
    }

    // Click handling
    canvas.addEventListener('click', (e) => {
      const mx = (e.clientX - offsetX) / scale;
      const my = (e.clientY - offsetY) / scale;

      for (const node of nodes) {
        const pos = positions[node.id];
        const dx = pos.x - mx;
        const dy = pos.y - my;
        if (Math.sqrt(dx * dx + dy * dy) < 15) {
          selectedNode = node.id;
          showPanel(node);
          draw();
          return;
        }
      }
      selectedNode = null;
      document.getElementById('info-panel').classList.remove('active');
    });

    function showPanel(node) {
      const panel = document.getElementById('info-panel');
      document.getElementById('panel-title').textContent = node.label;

      let html = '';
      html += '<div class="field"><span class="label">Risk</span><span class="value">' + node.risk.toUpperCase() + '</span></div>';
      html += '<div class="field"><span class="label">Group</span><span class="value">' + node.group + '</span></div>';
      html += '<div class="field"><span class="label">Policy</span><span class="value">' + (node.policy || 'N/A') + '</span></div>';
      html += '<div class="field"><span class="label">Capabilities</span></div>';
      html += '<div>';
      for (const cap of node.capabilities) {
        html += '<span class="cap-tag cap-' + cap + '">' + cap + '</span>';
      }
      if (node.capabilities.length === 0) html += '<span style="color:#555">none (pure compute)</span>';
      html += '</div>';

      document.getElementById('panel-content').innerHTML = html;
      panel.classList.add('active');
    }

    // Zoom
    canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const factor = e.deltaY > 0 ? 0.9 : 1.1;
      scale *= factor;
      draw();
    });

    // Pan
    let dragging = false, lastX, lastY;
    canvas.addEventListener('mousedown', (e) => { dragging = true; lastX = e.clientX; lastY = e.clientY; });
    canvas.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      offsetX += e.clientX - lastX;
      offsetY += e.clientY - lastY;
      lastX = e.clientX;
      lastY = e.clientY;
      draw();
    });
    canvas.addEventListener('mouseup', () => { dragging = false; });

    // Start
    draw();
  </script>
</body>
</html>`;
  }
}

module.exports = { DependencyMap };
