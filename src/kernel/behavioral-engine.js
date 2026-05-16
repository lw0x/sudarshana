'use strict';

/**
 * SUDARSHANA v2.0 — BEHAVIORAL CORRELATION ENGINE
 * 
 * The "missile brain." This doesn't match patterns — it catches INVARIANTS.
 * 
 * Fundamental truth: Every supply-chain attack MUST:
 *   1. READ something sensitive (env vars, files, credentials)
 *   2. SEND it somewhere (HTTP, DNS, file write to external path)
 * 
 * If we catch the COMBINATION — we catch ALL attacks.
 * Doesn't matter if they use eval, proxy, polymorphic code, AI-generated...
 * They CANNOT avoid reading + sending.
 * 
 * This engine tracks DATA FLOW, not individual operations.
 */

class BehavioralEngine {
  constructor(config = {}) {
    // Per-package behavior tracking
    this.packageBehavior = new Map();
    
    // Content hashes — track what data flows where
    this.contentHashes = new Map(); // hash → { source, package, timestamp }
    
    // Correlation rules
    this.rules = [
      ...DEFAULT_CORRELATION_RULES,
      ...(config.customRules || [])
    ];

    // Kill callbacks
    this.onCritical = config.onCritical || (() => {});
    this.violations = [];
  }

  /**
   * Record a package reading sensitive data
   */
  recordSensitiveRead(packageName, dataType, details = {}) {
    const behavior = this._getOrCreate(packageName);
    behavior.sensitiveReads.push({
      timestamp: Date.now(),
      dataType, // 'env_var', 'credential_file', 'private_key', 'proc_environ'
      target: details.target, // e.g., 'AWS_SECRET_ACCESS_KEY'
      contentHash: details.contentHash || null
    });

    // Track content hash for data flow
    if (details.contentHash) {
      this.contentHashes.set(details.contentHash, {
        source: dataType,
        target: details.target,
        package: packageName,
        timestamp: Date.now()
      });
    }

    this._evaluate(packageName);
  }

  /**
   * Record a package sending data outbound
   */
  recordOutboundSend(packageName, channel, details = {}) {
    const behavior = this._getOrCreate(packageName);
    behavior.outboundSends.push({
      timestamp: Date.now(),
      channel, // 'http', 'dns', 'smtp', 'tcp', 'file_to_external'
      destination: details.destination,
      payloadSize: details.payloadSize || 0,
      payloadHash: details.payloadHash || null,
      payloadEntropy: details.payloadEntropy || 0
    });

    // Check if outbound payload matches a previously read sensitive value
    if (details.payloadHash && this.contentHashes.has(details.payloadHash)) {
      const source = this.contentHashes.get(details.payloadHash);
      this._triggerCorrelation(packageName, 'DATA_FLOW_MATCH', {
        readPackage: source.package,
        readTarget: source.target,
        sendChannel: channel,
        sendDestination: details.destination,
        severity: 'CRITICAL',
        description: `Package "${packageName}" is exfiltrating sensitive data (${source.target}) via ${channel} to ${details.destination}`
      });
    }

    this._evaluate(packageName);
  }

  /**
   * Record file write (potential staging)
   */
  recordFileWrite(packageName, filePath, details = {}) {
    const behavior = this._getOrCreate(packageName);
    behavior.fileWrites.push({
      timestamp: Date.now(),
      path: filePath,
      contentHash: details.contentHash || null,
      size: details.size || 0
    });

    // Track content hash for staged exfil detection
    if (details.contentHash) {
      this.contentHashes.set(details.contentHash, {
        source: 'file_write',
        target: filePath,
        package: packageName,
        timestamp: Date.now()
      });
    }
  }

  /**
   * Record file read (check if it's a staged exfil read)
   */
  recordFileRead(packageName, filePath, details = {}) {
    if (details.contentHash && this.contentHashes.has(details.contentHash)) {
      const original = this.contentHashes.get(details.contentHash);
      if (original.source === 'env_var' || original.source === 'credential_file') {
        // This file contains previously read sensitive data!
        // If followed by outbound → staged exfil
        const behavior = this._getOrCreate(packageName);
        behavior.sensitiveReads.push({
          timestamp: Date.now(),
          dataType: 'staged_sensitive_data',
          target: `${original.target} (via ${filePath})`,
          contentHash: details.contentHash
        });
      }
    }
  }

  /**
   * Evaluate correlation rules for a package
   */
  _evaluate(packageName) {
    const behavior = this._getOrCreate(packageName);

    for (const rule of this.rules) {
      if (rule.evaluate(behavior, packageName)) {
        this._triggerCorrelation(packageName, rule.name, {
          severity: rule.severity,
          description: rule.describe(behavior, packageName)
        });
      }
    }
  }

  /**
   * Correlation triggered — this is the MISSILE FIRING
   */
  _triggerCorrelation(packageName, ruleName, details) {
    const violation = {
      timestamp: Date.now(),
      package: packageName,
      rule: ruleName,
      ...details
    };

    this.violations.push(violation);

    if (details.severity === 'CRITICAL') {
      this.onCritical(violation);
    }
  }

  _getOrCreate(packageName) {
    if (!this.packageBehavior.has(packageName)) {
      this.packageBehavior.set(packageName, {
        sensitiveReads: [],
        outboundSends: [],
        fileWrites: [],
        moduleLoads: [],
        firstSeen: Date.now()
      });
    }
    return this.packageBehavior.get(packageName);
  }

  /**
   * Get all violations
   */
  getViolations() {
    return [...this.violations];
  }

  /**
   * Get behavior summary for a package
   */
  getPackageBehavior(packageName) {
    return this.packageBehavior.get(packageName) || null;
  }
}

/**
 * DEFAULT CORRELATION RULES
 * 
 * These are the BEHAVIORAL INVARIANTS that catch attacks
 * regardless of technique, obfuscation, or polymorphism.
 */
const DEFAULT_CORRELATION_RULES = [
  {
    name: 'READ_THEN_SEND',
    severity: 'CRITICAL',
    evaluate: (behavior) => {
      // If package reads sensitive data AND sends outbound within 60s
      if (behavior.sensitiveReads.length === 0 || behavior.outboundSends.length === 0) return false;

      const latestRead = behavior.sensitiveReads[behavior.sensitiveReads.length - 1];
      const latestSend = behavior.outboundSends[behavior.outboundSends.length - 1];

      // Within 60 seconds of each other
      return Math.abs(latestSend.timestamp - latestRead.timestamp) < 60000;
    },
    describe: (behavior, pkg) => {
      const read = behavior.sensitiveReads[behavior.sensitiveReads.length - 1];
      const send = behavior.outboundSends[behavior.outboundSends.length - 1];
      return `[CRITICAL] "${pkg}" read sensitive data (${read.dataType}: ${read.target}) and sent outbound (${send.channel} → ${send.destination}) within 60s. This is the #1 indicator of data exfiltration.`;
    }
  },

  {
    name: 'BULK_ENV_READ',
    severity: 'HIGH',
    evaluate: (behavior) => {
      // Reading more than 5 env vars is suspicious for utility packages
      const envReads = behavior.sensitiveReads.filter(r => r.dataType === 'env_var');
      return envReads.length >= 5;
    },
    describe: (behavior, pkg) => {
      const envReads = behavior.sensitiveReads.filter(r => r.dataType === 'env_var');
      const targets = envReads.map(r => r.target).join(', ');
      return `[HIGH] "${pkg}" read ${envReads.length} sensitive env vars: ${targets}. Utility packages should not need this many secrets.`;
    }
  },

  {
    name: 'CREDENTIAL_FILE_THEN_NETWORK',
    severity: 'CRITICAL',
    evaluate: (behavior) => {
      const credReads = behavior.sensitiveReads.filter(r =>
        r.dataType === 'credential_file' || r.dataType === 'private_key'
      );
      return credReads.length > 0 && behavior.outboundSends.length > 0;
    },
    describe: (behavior, pkg) => {
      const credReads = behavior.sensitiveReads.filter(r =>
        r.dataType === 'credential_file' || r.dataType === 'private_key'
      );
      return `[CRITICAL] "${pkg}" read credential files (${credReads.map(r => r.target).join(', ')}) AND made outbound network requests. Highly likely data exfiltration.`;
    }
  },

  {
    name: 'STAGED_EXFILTRATION',
    severity: 'CRITICAL',
    evaluate: (behavior) => {
      // Write to temp → Read from temp → Send outbound
      if (behavior.fileWrites.length === 0 || behavior.outboundSends.length === 0) return false;

      for (const write of behavior.fileWrites) {
        if (write.contentHash) {
          // Check if this hash appears in outbound sends
          for (const send of behavior.outboundSends) {
            if (send.payloadHash === write.contentHash && send.timestamp > write.timestamp) {
              return true;
            }
          }
        }
      }
      return false;
    },
    describe: (behavior, pkg) => {
      return `[CRITICAL] "${pkg}" staged data through file system (write → read → exfil). Multi-step data exfiltration detected.`;
    }
  },

  {
    name: 'RAPID_MULTI_CHANNEL_EXFIL',
    severity: 'HIGH',
    evaluate: (behavior) => {
      // Using multiple channels (HTTP + DNS + file) within short time
      if (behavior.outboundSends.length < 2) return false;

      const channels = new Set(behavior.outboundSends.map(s => s.channel));
      const timeSpan = behavior.outboundSends[behavior.outboundSends.length - 1].timestamp -
                        behavior.outboundSends[0].timestamp;

      return channels.size >= 2 && timeSpan < 30000; // 2+ channels within 30s
    },
    describe: (behavior, pkg) => {
      const channels = [...new Set(behavior.outboundSends.map(s => s.channel))];
      return `[HIGH] "${pkg}" used multiple exfil channels (${channels.join(', ')}) within 30s. Multi-channel exfiltration pattern.`;
    }
  },

  {
    name: 'HIGH_ENTROPY_OUTBOUND',
    severity: 'MEDIUM',
    evaluate: (behavior) => {
      // Outbound data with high entropy = likely encrypted/encoded secrets
      return behavior.outboundSends.some(s => s.payloadEntropy > 4.5 && s.payloadSize > 20);
    },
    describe: (behavior, pkg) => {
      const highEntropy = behavior.outboundSends.filter(s => s.payloadEntropy > 4.5);
      return `[MEDIUM] "${pkg}" sent high-entropy data outbound (likely encoded/encrypted secrets). ${highEntropy.length} suspicious payloads detected.`;
    }
  },

  {
    name: 'TIMING_PATTERN_EXFIL',
    severity: 'MEDIUM',
    evaluate: (behavior) => {
      // Detect rhythmic sending pattern (timing-based covert channel)
      if (behavior.outboundSends.length < 8) return false;

      const intervals = [];
      for (let i = 1; i < behavior.outboundSends.length; i++) {
        intervals.push(behavior.outboundSends[i].timestamp - behavior.outboundSends[i - 1].timestamp);
      }

      // Check if intervals cluster around 2 values (binary encoding)
      const sorted = [...intervals].sort((a, b) => a - b);
      const median = sorted[Math.floor(sorted.length / 2)];
      const clusters = intervals.filter(i => Math.abs(i - median) < median * 0.3).length;

      return clusters > intervals.length * 0.7; // 70%+ requests follow pattern
    },
    describe: (behavior, pkg) => {
      return `[MEDIUM] "${pkg}" sends outbound requests with rhythmic timing pattern — possible timing-based covert channel for data exfiltration.`;
    }
  },

  {
    name: 'INSTALL_SCRIPT_NETWORK',
    severity: 'HIGH',
    evaluate: (behavior) => {
      // Any network access within first 5 seconds = likely install-time exfil
      const earlyNetwork = behavior.outboundSends.filter(s => 
        s.timestamp - behavior.firstSeen < 5000
      );
      return earlyNetwork.length > 0;
    },
    describe: (behavior, pkg) => {
      return `[HIGH] "${pkg}" made network requests within 5 seconds of loading. This is characteristic of install-time data theft (postinstall script pattern).`;
    }
  }
];

module.exports = { BehavioralEngine, DEFAULT_CORRELATION_RULES };
