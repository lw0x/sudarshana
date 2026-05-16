'use strict';

/**
 * SUDARSHANA — LEVEL 9: P2P THREAT NETWORK
 * 
 * "One Sudarshana catches a threat. ALL Sudarshanas block it instantly."
 * 
 * Privacy-preserving anonymous threat sharing:
 * - No user data, no project names, no IPs shared
 * - Only: {package, version, threat_type, hash, timestamp}
 * - Uses a simple HTTP-based pub/sub model
 * - Local fallback: file-based sharing (teams can share threat JSONs)
 * 
 * Architecture:
 * - Publisher: your Sudarshana → broadcasts threats when caught
 * - Subscriber: your Sudarshana → downloads latest threats on init/run
 * - Registry: lightweight endpoint (future: decentralized IPFS/DHT)
 * 
 * For now: file-based import/export + optional HTTP endpoint
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const NETWORK_CONFIG_FILE = '.sudarshana-network.json';
const THREAT_CACHE_DIR = '.sudarshana-threats';

class P2PThreatNetwork {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.config = this._loadConfig();
    this.localThreats = this._loadLocalThreats();
  }

  _loadConfig() {
    const configPath = path.join(this.projectRoot, NETWORK_CONFIG_FILE);
    if (fs.existsSync(configPath)) {
      try { return JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch(e) {}
    }
    return {
      enabled: true,
      peerId: crypto.randomBytes(16).toString('hex'),
      endpoints: [],
      autoPublish: true,
      autoSubscribe: true,
      lastSync: null
    };
  }

  _saveConfig() {
    const configPath = path.join(this.projectRoot, NETWORK_CONFIG_FILE);
    fs.writeFileSync(configPath, JSON.stringify(this.config, null, 2));
  }

  _loadLocalThreats() {
    const threatPath = path.join(this.projectRoot, THREAT_CACHE_DIR, 'known-threats.json');
    if (fs.existsSync(threatPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(threatPath, 'utf8'));
        return data.threats || [];
      } catch(e) {}
    }
    return [];
  }

  _saveLocalThreats() {
    const dir = path.join(this.projectRoot, THREAT_CACHE_DIR);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    const threatPath = path.join(dir, 'known-threats.json');
    fs.writeFileSync(threatPath, JSON.stringify({
      version: '1.0',
      lastUpdated: new Date().toISOString(),
      peerCount: this.config.endpoints.length,
      threats: this.localThreats
    }, null, 2));
  }

  /**
   * Publish a threat to the network
   */
  publish(threat) {
    // Sanitize — NEVER include user/project data
    const sanitized = {
      id: crypto.randomBytes(8).toString('hex'),
      package: threat.package,
      version: threat.version,
      threatType: threat.threatType,
      severity: threat.severity,
      hash: threat.hash || null,
      timestamp: new Date().toISOString(),
      // Anonymous origin (no identifying info)
      origin: crypto.createHash('sha256').update(this.config.peerId).digest('hex').substring(0, 8)
    };

    // Add to local cache
    const exists = this.localThreats.find(t =>
      t.package === sanitized.package && t.version === sanitized.version
    );
    if (!exists) {
      this.localThreats.push(sanitized);
      this._saveLocalThreats();
    }

    // Broadcast to configured endpoints (fire-and-forget)
    if (this.config.autoPublish && this.config.endpoints.length > 0) {
      this._broadcastToEndpoints(sanitized);
    }

    return sanitized;
  }

  /**
   * Subscribe — pull latest threats from network
   */
  async subscribe() {
    let imported = 0;

    for (const endpoint of this.config.endpoints) {
      try {
        const threats = await this._fetchFromEndpoint(endpoint);
        for (const threat of threats) {
          const exists = this.localThreats.find(t =>
            t.package === threat.package && t.version === threat.version
          );
          if (!exists) {
            this.localThreats.push(threat);
            imported++;
          }
        }
      } catch(e) {
        // Endpoint unreachable — skip silently
      }
    }

    if (imported > 0) {
      this._saveLocalThreats();
    }

    this.config.lastSync = new Date().toISOString();
    this._saveConfig();

    return { imported, total: this.localThreats.length };
  }

  /**
   * Import threats from a shared file (team sharing)
   */
  importFromFile(filePath) {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const threats = data.threats || data;
    let imported = 0;

    for (const threat of threats) {
      const exists = this.localThreats.find(t =>
        t.package === threat.package && t.version === threat.version
      );
      if (!exists && threat.package && threat.version) {
        this.localThreats.push({
          ...threat,
          importedAt: new Date().toISOString(),
          source: 'file-import'
        });
        imported++;
      }
    }

    this._saveLocalThreats();
    return { imported, total: this.localThreats.length };
  }

  /**
   * Export local threats for sharing with team
   */
  exportToFile(outputPath) {
    const exportData = {
      version: '1.0',
      exported: new Date().toISOString(),
      threatCount: this.localThreats.length,
      threats: this.localThreats.map(t => ({
        package: t.package,
        version: t.version,
        threatType: t.threatType,
        severity: t.severity,
        hash: t.hash,
        timestamp: t.timestamp
      }))
    };

    fs.writeFileSync(outputPath, JSON.stringify(exportData, null, 2));
    return { exported: this.localThreats.length, path: outputPath };
  }

  /**
   * Check if any installed packages match known threats
   */
  checkInstalled() {
    const pkgJsonPath = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return [];

    const projectPkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const allDeps = Object.keys({
      ...projectPkg.dependencies,
      ...projectPkg.devDependencies
    });

    const alerts = [];

    for (const dep of allDeps) {
      const depPkgPath = path.join(this.projectRoot, 'node_modules', dep, 'package.json');
      if (!fs.existsSync(depPkgPath)) continue;

      try {
        const depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf8'));
        const match = this.localThreats.find(t =>
          t.package === dep && t.version === depPkg.version
        );
        if (match) {
          alerts.push({ ...match, installed: true });
        }
      } catch(e) {}
    }

    return alerts;
  }

  /**
   * Add a peer endpoint
   */
  addEndpoint(url) {
    if (!this.config.endpoints.includes(url)) {
      this.config.endpoints.push(url);
      this._saveConfig();
    }
  }

  /**
   * Broadcast threat to all endpoints (non-blocking)
   */
  _broadcastToEndpoints(threat) {
    const https = require('https');
    const http = require('http');

    for (const endpoint of this.config.endpoints) {
      try {
        const url = new URL(endpoint);
        const mod = url.protocol === 'https:' ? https : http;
        const payload = JSON.stringify(threat);

        const req = mod.request({
          hostname: url.hostname,
          port: url.port,
          path: url.pathname,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Sudarshana-Peer': this.config.peerId.substring(0, 8)
          }
        });

        req.on('error', () => {}); // Silent fail
        req.write(payload);
        req.end();
      } catch(e) {}
    }
  }

  /**
   * Fetch threats from an endpoint
   */
  async _fetchFromEndpoint(endpoint) {
    return new Promise((resolve) => {
      try {
        const https = require('https');
        const http = require('http');
        const url = new URL(endpoint);
        const mod = url.protocol === 'https:' ? https : http;

        const req = mod.get(endpoint, (res) => {
          let data = '';
          res.on('data', chunk => { data += chunk; });
          res.on('end', () => {
            try { resolve(JSON.parse(data).threats || []); }
            catch(e) { resolve([]); }
          });
        });

        req.on('error', () => resolve([]));
        req.setTimeout(5000, () => { req.destroy(); resolve([]); });
      } catch(e) { resolve([]); }
    });
  }

  getStatus() {
    return {
      peerId: this.config.peerId.substring(0, 8),
      endpoints: this.config.endpoints.length,
      localThreats: this.localThreats.length,
      lastSync: this.config.lastSync,
      autoPublish: this.config.autoPublish,
      autoSubscribe: this.config.autoSubscribe
    };
  }
}

module.exports = { P2PThreatNetwork };
