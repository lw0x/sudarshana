'use strict';

/**
 * Configuration Loader
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_CONFIG = {
  packages: {},
  globals: {
    sensitive_files: ['.env', '*.pem', '*.key', 'id_rsa', 'id_ed25519', '.npmrc'],
    blocked_domains: ['*.ngrok.io', 'webhook.site', 'requestbin.com', 'burpcollaborator.net'],
    sensitive_env_patterns: ['AWS_SECRET*', 'DATABASE_*', 'PRIVATE_KEY*', '*_PASSWORD', '*_TOKEN'],
    max_dns_subdomain_length: 50,
    max_outbound_payload_bytes: 10240
  },
  thresholds: { critical: 30, high: 60, medium: 80 },
  defaultPolicy: 'deny-unknown',
  whitelist: [],
  blacklist: [],
  honeypots: null,
  alertWebhook: null,
  enforce: false
};

class Config {
  static load(configPath) {
    const searchPaths = [
      configPath,
      path.resolve(process.cwd(), '.sudarshana.json'),
      path.resolve(process.cwd(), 'sudarshana.config.json'),
      path.resolve(process.env.HOME || '', '.sudarshana.json')
    ].filter(Boolean);

    for (const p of searchPaths) {
      try {
        if (fs.existsSync(p)) {
          const raw = fs.readFileSync(p, 'utf8');
          const userConfig = JSON.parse(raw);
          return Config.merge(DEFAULT_CONFIG, userConfig);
        }
      } catch (e) {
        // Skip invalid configs
      }
    }

    return { ...DEFAULT_CONFIG };
  }

  static merge(defaults, overrides) {
    const result = { ...defaults };
    for (const [key, value] of Object.entries(overrides)) {
      if (value && typeof value === 'object' && !Array.isArray(value) && defaults[key]) {
        result[key] = Config.merge(defaults[key], value);
      } else {
        result[key] = value;
      }
    }
    return result;
  }
}

module.exports = Config;
