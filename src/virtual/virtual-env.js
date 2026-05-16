'use strict';

/**
 * SUDARSHANA v2.0 — VIRTUAL ENVIRONMENT
 * 
 * Per-package process.env isolation.
 * Each package sees ONLY the env vars its policy allows.
 * The rest of the universe is invisible.
 * 
 * KEY: We DON'T "block" access. The variable simply doesn't exist.
 * process.env.AWS_SECRET returns undefined (not "ACCESS DENIED").
 * Object.keys(process.env) returns only visible vars.
 * 
 * ANTI-FINGERPRINTING: The package can't tell it's sandboxed.
 * It just looks like a minimal environment (common in containers).
 * 
 * ALSO PROTECTS: /proc/self/environ bypass (handled in virtual-fs)
 */

const crypto = require('crypto');

/**
 * Create a per-package virtual environment
 * Returns a Proxy that filters process.env access
 */
function createVirtualEnv(packageName, policy, behavioralEngine) {
  const visibleVars = policy.env_visible || [];
  const realEnv = process.env;

  // Determine which vars this package can see
  const canSee = (varName) => {
    if (typeof varName !== 'string') return false;
    if (policy.env_all) return true;
    if (visibleVars.includes('*')) return true;
    if (visibleVars.includes(varName)) return true;

    // Check glob patterns
    for (const pattern of visibleVars) {
      if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$', 'i');
        if (regex.test(varName)) return true;
      }
    }
    return false;
  };

  // Determine if a var is sensitive (for behavioral tracking)
  const isSensitive = (varName) => {
    const sensitivePatterns = [
      /^AWS_/i, /SECRET/i, /TOKEN/i, /PASSWORD/i, /KEY/i, /PRIVATE/i,
      /DATABASE_URL/i, /^DB_/i, /REDIS_/i, /MONGO/i, /MYSQL/i,
      /API_KEY/i, /STRIPE/i, /TWILIO/i, /SENDGRID/i, /^AUTH/i,
      /GITHUB_TOKEN/i, /NPM_TOKEN/i, /CI_TOKEN/i
    ];
    return sensitivePatterns.some(p => p.test(varName));
  };

  return new Proxy({}, {
    get(_, prop) {
      if (typeof prop === 'symbol') return undefined;
      if (typeof prop !== 'string') return undefined;

      // Allow access to non-sensitive vars that are in visible list
      if (canSee(prop)) {
        // Track sensitive reads for behavioral analysis
        if (isSensitive(prop) && behavioralEngine && realEnv[prop]) {
          const contentHash = crypto.createHash('sha256')
            .update(String(realEnv[prop]))
            .digest('hex')
            .substring(0, 16);

          behavioralEngine.recordSensitiveRead(packageName, 'env_var', {
            target: prop,
            contentHash
          });
        }
        return realEnv[prop];
      }

      // Variable doesn't exist in this package's reality
      return undefined;
    },

    set(_, prop, value) {
      if (typeof prop !== 'string') return true;
      if (canSee(prop)) {
        realEnv[prop] = value;
      }
      // Silently ignore writes to invisible vars (don't error)
      return true;
    },

    has(_, prop) {
      if (typeof prop !== 'string') return false;
      return canSee(prop) && (prop in realEnv);
    },

    ownKeys() {
      return Object.keys(realEnv).filter(k => canSee(k));
    },

    getOwnPropertyDescriptor(_, prop) {
      if (typeof prop !== 'string') return undefined;
      if (canSee(prop) && prop in realEnv) {
        return { value: realEnv[prop], writable: true, enumerable: true, configurable: true };
      }
      return undefined;
    },

    deleteProperty(_, prop) {
      if (typeof prop !== 'string') return true;
      if (canSee(prop)) {
        delete realEnv[prop];
      }
      return true;
    },

    // Prevent enumeration tricks
    getPrototypeOf() { return Object.prototype; },
    setPrototypeOf() { return true; },
    isExtensible() { return true; },
    preventExtensions() { return false; },
    defineProperty() { return true; }
  });
}

/**
 * Create HONEYPOT env vars — fake secrets that trigger instant detection
 * If any package reads these, it's DEFINITELY malicious (zero false positives)
 */
function createHoneypotVars() {
  const honeypots = {
    'AWS_SECRET_ACCESS_KEY_BACKUP': 'sudarshana-trap-' + crypto.randomBytes(16).toString('hex'),
    'DB_ADMIN_PASSWORD': 'sudarshana-trap-' + crypto.randomBytes(16).toString('hex'),
    'GITHUB_PERSONAL_TOKEN': 'ghp_' + crypto.randomBytes(20).toString('hex'),
    'STRIPE_LIVE_SECRET': 'sk_live_' + crypto.randomBytes(16).toString('hex'),
    'NPM_AUTH_TOKEN_OLD': 'npm_' + crypto.randomBytes(24).toString('base64'),
    'INTERNAL_API_MASTER_KEY': 'sudarshana-trap-' + crypto.randomBytes(16).toString('hex')
  };

  // Mark these as traps
  const trapHashes = new Map();
  for (const [key, value] of Object.entries(honeypots)) {
    trapHashes.set(
      crypto.createHash('sha256').update(value).digest('hex').substring(0, 16),
      key
    );
  }

  return { honeypots, trapHashes };
}

/**
 * Enhanced virtual env with honeypot integration
 */
function createVirtualEnvWithHoneypots(packageName, policy, behavioralEngine) {
  const baseEnv = createVirtualEnv(packageName, policy, behavioralEngine);
  const { honeypots, trapHashes } = createHoneypotVars();

  // Register trap hashes with behavioral engine
  if (behavioralEngine) {
    for (const [hash, varName] of trapHashes) {
      // If this hash ever appears in outbound data → INSTANT KILL
      behavioralEngine.contentHashes.set(hash, {
        source: 'honeypot',
        target: varName,
        package: '_HONEYPOT_',
        timestamp: Date.now()
      });
    }
  }

  // Wrap base env to include honeypots as visible traps
  return new Proxy(baseEnv, {
    get(target, prop) {
      if (typeof prop === 'string' && honeypots[prop]) {
        // A package accessed a honeypot! 100% malicious.
        if (behavioralEngine) {
          const hash = crypto.createHash('sha256')
            .update(honeypots[prop]).digest('hex').substring(0, 16);

          behavioralEngine.recordSensitiveRead(packageName, 'honeypot', {
            target: prop,
            contentHash: hash
          });

          // Immediate critical alert
          behavioralEngine._triggerCorrelation(packageName, 'HONEYPOT_ACCESS', {
            severity: 'CRITICAL',
            description: `Package "${packageName}" accessed honeypot env var "${prop}". This is DEFINITIVE proof of malicious credential harvesting. Zero false positive rate.`
          });
        }
        return honeypots[prop]; // Return the trap value (to track if exfiltrated)
      }
      return Reflect.get(target, prop);
    },

    has(target, prop) {
      if (typeof prop === 'string' && honeypots[prop]) return true;
      return Reflect.has(target, prop);
    },

    ownKeys(target) {
      // Don't show honeypots in Object.keys() — only triggered by direct access
      return Reflect.ownKeys(target);
    }
  });
}

module.exports = { createVirtualEnv, createVirtualEnvWithHoneypots, createHoneypotVars };
