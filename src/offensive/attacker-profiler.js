'use strict';

/**
 * SUDARSHANA — LEVEL 11: ATTACKER FINGERPRINTING
 * 
 * "We don't just catch you. We learn you. Forever."
 * 
 * When a honeypot or decoy triggers, we build a profile:
 * - Attack timing patterns (UTC offset, working hours)
 * - Encoding preferences (base64? hex? URL-encoded?)
 * - C2 domain structure (*.evil.com? IP-based? DNS tunnel?)
 * - Target selection (which env vars? which files?)
 * - Evasion techniques (delayed? chunked? encoded?)
 * 
 * This creates an "Attacker DNA" — recognizable across
 * different packages, different projects, different times.
 * 
 * Like a criminal's MO — even if they use a new tool,
 * we recognize the human behind it.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class AttackerProfiler {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.profilesDir = path.join(this.projectRoot, '.sudarshana-intel', 'profiles');
    this.profiles = this._loadProfiles();
  }

  _ensureDir() {
    if (!fs.existsSync(this.profilesDir)) fs.mkdirSync(this.profilesDir, { recursive: true });
  }

  _loadProfiles() {
    this._ensureDir();
    const indexPath = path.join(this.profilesDir, 'index.json');
    if (fs.existsSync(indexPath)) {
      try { return JSON.parse(fs.readFileSync(indexPath, 'utf8')); } catch(e) {}
    }
    return { profiles: [], lastUpdated: null };
  }

  _saveProfiles() {
    this.profiles.lastUpdated = new Date().toISOString();
    fs.writeFileSync(
      path.join(this.profilesDir, 'index.json'),
      JSON.stringify(this.profiles, null, 2)
    );
  }

  /**
   * Analyze an attack event and build/update attacker profile
   */
  profileAttack(attackEvent) {
    const {
      package: packageName,
      threatType,
      evidence = {},
      timestamp = new Date().toISOString()
    } = attackEvent;

    const fingerprint = this._extractFingerprint(attackEvent);

    // Check if this matches an existing profile
    const matchedProfile = this._matchProfile(fingerprint);

    if (matchedProfile) {
      // Update existing profile
      matchedProfile.sightings++;
      matchedProfile.lastSeen = timestamp;
      matchedProfile.packages.push(packageName);
      matchedProfile.packages = [...new Set(matchedProfile.packages)];
      matchedProfile.techniques = this._mergeTechniques(matchedProfile.techniques, fingerprint.techniques);
      this._saveProfiles();
      return { action: 'UPDATED', profile: matchedProfile };
    } else {
      // Create new profile
      const newProfile = {
        id: 'APT-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
        firstSeen: timestamp,
        lastSeen: timestamp,
        sightings: 1,
        fingerprint,
        packages: [packageName],
        techniques: fingerprint.techniques,
        threatLevel: this._assessThreatLevel(fingerprint),
        confidence: 'LOW' // increases with more sightings
      };

      this.profiles.profiles.push(newProfile);
      this._saveProfiles();
      return { action: 'CREATED', profile: newProfile };
    }
  }

  /**
   * Extract behavioral fingerprint from an attack event
   */
  _extractFingerprint(event) {
    const evidence = event.evidence || {};

    return {
      // Timing analysis
      timing: {
        hourOfDay: new Date(event.timestamp).getUTCHours(),
        dayOfWeek: new Date(event.timestamp).getUTCDay(),
        timezone_hint: this._guessTimezone(event.timestamp)
      },

      // Target selection pattern
      targets: {
        envVars: evidence.envVarsAccessed || [],
        filePaths: evidence.filesAccessed || [],
        domains: evidence.domainsContacted || [],
        targetTypes: this._classifyTargets(evidence)
      },

      // Encoding/obfuscation style
      encoding: {
        usesBase64: evidence.usesBase64 || false,
        usesHex: evidence.usesHex || false,
        usesUnicode: evidence.usesUnicode || false,
        usesConcat: evidence.usesConcat || false,
        obfuscationLevel: evidence.obfuscationScore || 0
      },

      // C2 communication style
      c2Pattern: {
        domainStyle: this._classifyDomains(evidence.domainsContacted || []),
        protocol: evidence.protocol || 'unknown',
        useDnsTunneling: evidence.dnsTunneling || false,
        useHttpHeaders: evidence.exfilViaHeaders || false,
        chunkSize: evidence.chunkSize || 0
      },

      // Evasion techniques
      techniques: this._identifyTechniques(evidence)
    };
  }

  /**
   * Match a fingerprint against existing profiles
   * Returns matched profile or null
   */
  _matchProfile(fingerprint) {
    for (const profile of this.profiles.profiles) {
      const similarity = this._calculateSimilarity(profile.fingerprint, fingerprint);
      if (similarity > 0.7) { // 70% match threshold
        return profile;
      }
    }
    return null;
  }

  /**
   * Calculate similarity between two fingerprints (0-1)
   */
  _calculateSimilarity(a, b) {
    let score = 0;
    let factors = 0;

    // Timing similarity (same working hours?)
    if (Math.abs(a.timing.hourOfDay - b.timing.hourOfDay) <= 2) { score += 1; }
    factors++;

    // Target overlap
    const aTargetTypes = new Set(a.targets.targetTypes || []);
    const bTargetTypes = new Set(b.targets.targetTypes || []);
    const targetOverlap = [...aTargetTypes].filter(t => bTargetTypes.has(t)).length;
    if (targetOverlap > 0) { score += targetOverlap / Math.max(aTargetTypes.size, bTargetTypes.size); }
    factors++;

    // Encoding style match
    if (a.encoding.usesBase64 === b.encoding.usesBase64) score += 0.5;
    if (a.encoding.usesHex === b.encoding.usesHex) score += 0.5;
    factors++;

    // C2 pattern match
    if (a.c2Pattern.domainStyle === b.c2Pattern.domainStyle) score += 1;
    if (a.c2Pattern.useDnsTunneling === b.c2Pattern.useDnsTunneling) score += 0.5;
    factors += 1.5;

    // Technique overlap
    const aTech = new Set(a.techniques || []);
    const bTech = new Set(b.techniques || []);
    const techOverlap = [...aTech].filter(t => bTech.has(t)).length;
    if (techOverlap > 0) { score += techOverlap / Math.max(aTech.size, bTech.size, 1); }
    factors++;

    return factors > 0 ? score / factors : 0;
  }

  /**
   * Classify what types of data the attacker targets
   */
  _classifyTargets(evidence) {
    const types = new Set();
    const envVars = evidence.envVarsAccessed || [];
    const files = evidence.filesAccessed || [];

    for (const v of envVars) {
      if (/AWS|CLOUD|GCP|AZURE/i.test(v)) types.add('cloud_credentials');
      if (/DATABASE|DB_|REDIS|MONGO/i.test(v)) types.add('database_credentials');
      if (/TOKEN|AUTH|JWT/i.test(v)) types.add('auth_tokens');
      if (/STRIPE|PAYMENT/i.test(v)) types.add('payment_keys');
      if (/GITHUB|NPM|GIT/i.test(v)) types.add('developer_tokens');
      if (/CRYPTO|WALLET|PRIVATE_KEY/i.test(v)) types.add('crypto_keys');
    }

    for (const f of files) {
      if (/\.ssh|id_rsa|id_ed25519/i.test(f)) types.add('ssh_keys');
      if (/\.aws|credentials/i.test(f)) types.add('cloud_credentials');
      if (/wallet|keystore/i.test(f)) types.add('crypto_keys');
      if (/\.env/i.test(f)) types.add('env_files');
    }

    return [...types];
  }

  /**
   * Classify C2 domain patterns
   */
  _classifyDomains(domains) {
    if (domains.length === 0) return 'none';

    const patterns = domains.map(d => {
      if (/^\d+\.\d+\.\d+\.\d+$/.test(d)) return 'raw_ip';
      if (/\.ngrok|\.pipedream|\.webhook\.site|\.requestbin/i.test(d)) return 'disposable_service';
      if (/^[a-z0-9]{20,}\./.test(d)) return 'generated_subdomain';
      if (d.split('.').length > 4) return 'dns_tunnel';
      return 'registered_domain';
    });

    // Most common pattern
    const counts = {};
    for (const p of patterns) counts[p] = (counts[p] || 0) + 1;
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
  }

  /**
   * Identify evasion techniques used
   */
  _identifyTechniques(evidence) {
    const techniques = [];

    if (evidence.delayedExecution) techniques.push('DELAYED_EXECUTION');
    if (evidence.conditionalTrigger) techniques.push('CONDITIONAL_TRIGGER');
    if (evidence.obfuscationScore > 50) techniques.push('HEAVY_OBFUSCATION');
    if (evidence.dnsTunneling) techniques.push('DNS_TUNNELING');
    if (evidence.exfilViaHeaders) techniques.push('HEADER_EXFILTRATION');
    if (evidence.chunkedSend) techniques.push('CHUNKED_EXFILTRATION');
    if (evidence.multiStage) techniques.push('STAGED_ATTACK');
    if (evidence.usesWebSocket) techniques.push('WEBSOCKET_C2');
    if (evidence.encodingLayers > 1) techniques.push('MULTI_LAYER_ENCODING');
    if (evidence.antiDebug) techniques.push('ANTI_DEBUGGING');
    if (evidence.vmDetection) techniques.push('VM_DETECTION');
    if (evidence.timingEvasion) techniques.push('TIMING_EVASION');

    return techniques;
  }

  _mergeTechniques(existing, newTechniques) {
    return [...new Set([...existing, ...newTechniques])];
  }

  _guessTimezone(timestamp) {
    const hour = new Date(timestamp).getUTCHours();
    // Working hours heuristic
    if (hour >= 1 && hour <= 9) return 'UTC+5:30 to UTC+8 (Asia)';
    if (hour >= 8 && hour <= 17) return 'UTC+0 to UTC+2 (Europe)';
    if (hour >= 14 && hour <= 23) return 'UTC-5 to UTC-8 (Americas)';
    return 'UNKNOWN';
  }

  _assessThreatLevel(fingerprint) {
    let level = 'LOW';
    if (fingerprint.techniques.length >= 3) level = 'MEDIUM';
    if (fingerprint.techniques.length >= 5) level = 'HIGH';
    if (fingerprint.techniques.includes('MULTI_LAYER_ENCODING') ||
        fingerprint.techniques.includes('STAGED_ATTACK')) level = 'HIGH';
    if (fingerprint.c2Pattern.useDnsTunneling) level = 'HIGH';
    return level;
  }

  /**
   * Get all profiles as a report
   */
  getReport() {
    const lines = [];
    lines.push('');
    lines.push('⚔️  SUDARSHANA — Attacker Intelligence Report');
    lines.push('═'.repeat(55));
    lines.push(`  Known threat actors: ${this.profiles.profiles.length}`);
    lines.push('');

    for (const profile of this.profiles.profiles) {
      const icon = profile.threatLevel === 'HIGH' ? '🔴' : profile.threatLevel === 'MEDIUM' ? '🟠' : '🟡';
      lines.push(`  ${icon} ${profile.id} — ${profile.threatLevel}`);
      lines.push(`     First seen: ${profile.firstSeen}`);
      lines.push(`     Sightings: ${profile.sightings}`);
      lines.push(`     Packages targeted: ${profile.packages.join(', ')}`);
      lines.push(`     Techniques: ${profile.techniques.join(', ') || 'unknown'}`);
      lines.push(`     Timezone hint: ${profile.fingerprint.timing.timezone_hint}`);
      lines.push('');
    }

    if (this.profiles.profiles.length === 0) {
      lines.push('  ✅ No threat actors profiled yet.');
      lines.push('  Deploy honeypots to start catching attackers.');
      lines.push('');
    }

    return lines.join('\n');
  }
}

module.exports = { AttackerProfiler };
