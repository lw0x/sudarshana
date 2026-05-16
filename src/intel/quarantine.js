'use strict';

/**
 * SUDARSHANA — QUARANTINE MODE
 * 
 * "Don't kill the app. Isolate the threat. Keep serving users."
 * 
 * When a package triggers a CRITICAL alert (confirmed exfiltration,
 * honeypot access, etc.), instead of killing the entire process:
 * 
 * 1. FREEZE the package — all future calls return safe defaults
 * 2. ALERT the security team — webhook/log
 * 3. CONTINUE the app — users never notice
 * 4. LOG everything — forensics data preserved
 * 
 * This is the "production mode" response. In dev/CI, you kill.
 * In production, you quarantine.
 * 
 * Post-quarantine, the package is in a "phantom zone":
 * - require() returns an empty object
 * - All methods return undefined/empty
 * - Network calls silently succeed (return empty responses)
 * - No errors thrown (app stays stable)
 */

const path = require('path');
const fs = require('fs');

class QuarantineManager {
  constructor() {
    // Set of quarantined package names
    this.quarantined = new Set();

    // Quarantine log (forensics)
    this.log = [];

    // Webhook URL for alerts
    this.webhookUrl = null;

    // Callback for custom alert handling
    this.alertHandlers = [];
  }

  /**
   * Configure quarantine settings
   */
  configure(options = {}) {
    if (options.webhookUrl) this.webhookUrl = options.webhookUrl;
  }

  /**
   * Register an alert handler
   */
  onQuarantine(handler) {
    this.alertHandlers.push(handler);
  }

  /**
   * Quarantine a package — isolate it immediately
   * @param {string} packageName 
   * @param {string} reason 
   * @param {Object} evidence - forensics data
   */
  quarantine(packageName, reason, evidence = {}) {
    if (this.quarantined.has(packageName)) return; // Already quarantined

    this.quarantined.add(packageName);

    const entry = {
      package: packageName,
      reason,
      evidence,
      timestamp: new Date().toISOString(),
      unixTime: Date.now()
    };

    this.log.push(entry);

    // Emit alerts
    for (const handler of this.alertHandlers) {
      try { handler(entry); } catch (e) { /* don't let handler crash us */ }
    }

    // Send webhook (non-blocking)
    if (this.webhookUrl) {
      this._sendWebhook(entry);
    }

    // Write to quarantine log file
    this._writeLog(entry);

    return entry;
  }

  /**
   * Check if a package is quarantined
   */
  isQuarantined(packageName) {
    return this.quarantined.has(packageName);
  }

  /**
   * Get a "phantom" module for a quarantined package
   * Returns a Proxy that silently absorbs all operations
   */
  getPhantomModule(packageName) {
    const self = this;

    // Deep phantom — every property access returns another phantom
    // Every function call returns undefined
    // No errors ever thrown
    const phantomHandler = {
      get(target, prop) {
        // Log access attempts for forensics
        self._logAccess(packageName, prop);

        if (prop === Symbol.toPrimitive) return () => '';
        if (prop === 'toString') return () => '[quarantined]';
        if (prop === 'valueOf') return () => 0;
        if (prop === 'then') return undefined; // Don't look like a Promise

        // Return a callable phantom for any property
        return new Proxy(function() {}, phantomHandler);
      },

      apply(target, thisArg, args) {
        // Any function call on quarantined module returns empty/safe defaults
        return undefined;
      },

      construct(target, args) {
        // new QuarantinedClass() returns empty object
        return new Proxy({}, phantomHandler);
      },

      set(target, prop, value) {
        // Silently absorb writes
        return true;
      },

      has(target, prop) {
        return false;
      },

      ownKeys(target) {
        return [];
      },

      getOwnPropertyDescriptor(target, prop) {
        return undefined;
      }
    };

    return new Proxy(function() {}, phantomHandler);
  }

  /**
   * Log quarantined package access attempts (forensics)
   */
  _logAccess(packageName, property) {
    // Rate-limit logging to prevent flood
    const key = `${packageName}:${String(property)}`;
    if (!this._accessLog) this._accessLog = new Map();
    
    const count = (this._accessLog.get(key) || 0) + 1;
    this._accessLog.set(key, count);

    // Only log first 10 unique accesses per package
    if (count <= 10) {
      this.log.push({
        type: 'phantom_access',
        package: packageName,
        property: String(property),
        timestamp: new Date().toISOString(),
        count
      });
    }
  }

  /**
   * Write quarantine event to disk
   */
  _writeLog(entry) {
    try {
      const logDir = path.join(process.cwd(), '.sudarshana-quarantine');
      if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

      const logFile = path.join(logDir, 'quarantine.jsonl');
      fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
    } catch (e) {
      // Don't crash if we can't write log
    }
  }

  /**
   * Send webhook alert (fire-and-forget, non-blocking)
   */
  _sendWebhook(entry) {
    try {
      const https = require('https');
      const url = new URL(this.webhookUrl);

      const payload = JSON.stringify({
        text: `🚨 SUDARSHANA QUARANTINE: \`${entry.package}\` isolated`,
        blocks: [
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*🚨 Package Quarantined*\n` +
                    `*Package:* \`${entry.package}\`\n` +
                    `*Reason:* ${entry.reason}\n` +
                    `*Time:* ${entry.timestamp}\n` +
                    `*Status:* Isolated — app continues running`
            }
          }
        ]
      });

      const req = https.request({
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });

      req.on('error', () => {}); // Silent fail
      req.write(payload);
      req.end();
    } catch (e) {
      // Non-critical — don't crash
    }
  }

  /**
   * Get quarantine status report
   */
  getStatus() {
    return {
      quarantinedCount: this.quarantined.size,
      packages: [...this.quarantined],
      log: this.log.filter(e => e.type !== 'phantom_access'),
      phantomAccesses: this.log.filter(e => e.type === 'phantom_access').length
    };
  }
}

module.exports = { QuarantineManager };
