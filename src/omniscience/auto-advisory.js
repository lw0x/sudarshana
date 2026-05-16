'use strict';

/**
 * SUDARSHANA — LEVEL 12: AUTOMATED ADVISORY GENERATION
 * 
 * "0-human incident response. The disc files the report."
 * 
 * On confirmed malicious package:
 * 1. Generate GitHub Security Advisory (GHSA format)
 * 2. Generate CVE report (NVD format)
 * 3. Generate npm abuse report
 * 4. Generate internal incident report
 * 
 * All auto-filled with evidence from:
 * - Honeypot access logs
 * - Behavioral correlation data
 * - Content hash tracking
 * - Attacker profile
 * - Drift detection results
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class AutoAdvisory {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.outputDir = path.join(this.projectRoot, '.sudarshana-advisories');
  }

  _ensureDir() {
    if (!fs.existsSync(this.outputDir)) fs.mkdirSync(this.outputDir, { recursive: true });
  }

  /**
   * Generate all advisory formats for a confirmed malicious package
   */
  generate(incident) {
    this._ensureDir();

    const {
      package: packageName,
      version,
      threatType,
      severity,
      evidence = {},
      timestamp = new Date().toISOString()
    } = incident;

    const advisoryId = `SUDARSHANA-${Date.now().toString(36).toUpperCase()}`;

    const results = {
      advisoryId,
      package: packageName,
      version,
      generated: timestamp,
      reports: {}
    };

    // 1. GitHub Security Advisory format
    results.reports.ghsa = this._generateGHSA(advisoryId, incident);

    // 2. CVE-style report
    results.reports.cve = this._generateCVE(advisoryId, incident);

    // 3. npm abuse report
    results.reports.npmAbuse = this._generateNpmAbuse(incident);

    // 4. Internal incident report
    results.reports.internal = this._generateInternalReport(advisoryId, incident);

    // Save all reports
    const outputPath = path.join(this.outputDir, `${advisoryId}.json`);
    fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));

    // Also save human-readable markdown
    const mdPath = path.join(this.outputDir, `${advisoryId}.md`);
    fs.writeFileSync(mdPath, this._generateMarkdown(advisoryId, incident));

    return results;
  }

  /**
   * GitHub Security Advisory format (GHSA)
   */
  _generateGHSA(advisoryId, incident) {
    const { package: pkg, version, threatType, severity, evidence = {} } = incident;

    return {
      schema_version: '1.4.0',
      id: advisoryId,
      summary: `Malicious code in ${pkg}@${version} — ${this._threatDescription(threatType)}`,
      details: this._buildDetails(incident),
      severity: this._mapSeverityCVSS(severity),
      affected: [{
        package: {
          ecosystem: 'npm',
          name: pkg
        },
        ranges: [{
          type: 'SEMVER',
          events: [
            { introduced: version },
            { fixed: '' } // Unknown fix version
          ]
        }],
        versions: [version]
      }],
      references: [],
      database_specific: {
        detected_by: 'sudarshana',
        detection_method: threatType,
        evidence_hash: evidence.hash || null,
        detection_timestamp: incident.timestamp
      }
    };
  }

  /**
   * CVE-style report (NVD JSON format)
   */
  _generateCVE(advisoryId, incident) {
    const { package: pkg, version, threatType, severity } = incident;

    return {
      dataType: 'CVE_RECORD',
      dataVersion: '5.0',
      cveMetadata: {
        cveId: `CVE-PENDING-${advisoryId}`,
        state: 'DRAFT',
        dateReserved: new Date().toISOString(),
        datePublished: null
      },
      containers: {
        cna: {
          providerMetadata: {
            orgId: 'sudarshana-automated',
            shortName: 'SUDARSHANA'
          },
          title: `Supply chain attack via ${pkg}@${version}`,
          descriptions: [{
            lang: 'en',
            value: this._buildDetails(incident)
          }],
          affected: [{
            vendor: 'npm',
            product: pkg,
            versions: [{
              version: version,
              status: 'affected'
            }]
          }],
          metrics: [{
            cvssV3_1: {
              vectorString: this._generateCVSSVector(severity, threatType),
              baseScore: this._mapSeverityScore(severity)
            }
          }],
          problemTypes: [{
            descriptions: [{
              type: 'CWE',
              cweId: this._mapCWE(threatType),
              description: this._threatDescription(threatType)
            }]
          }]
        }
      }
    };
  }

  /**
   * npm abuse report format
   */
  _generateNpmAbuse(incident) {
    const { package: pkg, version, threatType, evidence = {} } = incident;

    return {
      reportType: 'malware',
      package: pkg,
      version,
      description: `Sudarshana automated detection: ${this._threatDescription(threatType)} detected in ${pkg}@${version}. ` +
                   `Detection method: ${threatType}. This package should be unpublished immediately.`,
      evidence: {
        detectionMethod: threatType,
        honeypotTriggered: threatType === 'HONEYPOT_ACCESS',
        exfiltrationAttempt: threatType.includes('EXFIL'),
        behavioralCorrelation: threatType === 'READ_THEN_SEND',
        timestamp: incident.timestamp
      },
      reportedBy: 'sudarshana-automated-detection',
      submissionUrl: 'https://www.npmjs.com/support'
    };
  }

  /**
   * Internal incident report
   */
  _generateInternalReport(advisoryId, incident) {
    const { package: pkg, version, threatType, severity, evidence = {} } = incident;

    return {
      incidentId: advisoryId,
      classification: severity,
      summary: `Malicious package detected: ${pkg}@${version}`,
      timeline: [
        { time: incident.timestamp, event: `${threatType} detected by Sudarshana` },
        { time: incident.timestamp, event: 'Package automatically quarantined' },
        { time: new Date().toISOString(), event: 'Advisory generated' }
      ],
      impact: {
        dataExposed: threatType.includes('EXFIL') ? 'POSSIBLE — check content tracker logs' : 'NONE (blocked by sandbox)',
        systemsAffected: 'Current project only (sandboxed)',
        userImpact: 'None (quarantine prevented execution)'
      },
      remediation: {
        immediate: [
          `Package ${pkg} quarantined (phantom module active)`,
          'No credentials were exposed (honeypot values only)'
        ],
        shortTerm: [
          `Pin ${pkg} to last known good version`,
          'Run `npm audit` for related advisories',
          'Check if other projects use this package'
        ],
        longTerm: [
          'Report to npm security team',
          'Add package to threat feed for network-wide protection',
          'Review dependency policy for this category of packages'
        ]
      },
      evidence: {
        detectionMethod: threatType,
        ...evidence
      }
    };
  }

  /**
   * Generate human-readable markdown report
   */
  _generateMarkdown(advisoryId, incident) {
    const { package: pkg, version, threatType, severity, evidence = {} } = incident;

    return `# Security Advisory: ${advisoryId}

## Summary

**Malicious code detected** in \`${pkg}@${version}\`

| Field | Value |
|-------|-------|
| Package | ${pkg} |
| Version | ${version} |
| Severity | ${severity} |
| Threat Type | ${threatType} |
| Detected | ${incident.timestamp} |
| Detection Method | Sudarshana Automated |

## Description

${this._buildDetails(incident)}

## Impact

${threatType.includes('EXFIL') ? '⚠️ Data exfiltration attempted — blocked by Sudarshana sandbox.' : '✅ Attack blocked before any impact.'}

## Remediation

1. Package has been quarantined (phantom module active)
2. Pin to last known good version: \`npm install ${pkg}@"<${version}" --save-exact\`
3. Clear npm cache: \`npm cache clean ${pkg} --force\`
4. Report to npm: https://www.npmjs.com/support

## Evidence

- Detection method: ${threatType}
- Honeypot triggered: ${threatType === 'HONEYPOT_ACCESS' ? 'Yes' : 'No'}
- Behavioral correlation: ${threatType === 'READ_THEN_SEND' ? 'Yes' : 'No'}

---

*Generated by Sudarshana — the disc doesn't warn, it severs.*
`;
  }

  // Helper methods

  _threatDescription(type) {
    const descriptions = {
      'HONEYPOT_ACCESS': 'Credential theft attempt (honeypot triggered)',
      'READ_THEN_SEND': 'Data exfiltration (read sensitive → send outbound)',
      'SENSITIVE_DATA_EXFILTRATION': 'Direct sensitive data exfiltration',
      'STAGED_EXFILTRATION': 'Staged data exfiltration via intermediate storage',
      'CONTENT_MUTATED_SAME_VERSION': 'Package content tampered (same version, different files)',
      'NEW_DANGEROUS_IMPORT': 'Sudden dangerous capability added',
      'INSTALL_SCRIPT_ATTACK': 'Malicious install script execution',
      'DNS_TUNNELING': 'Data exfiltration via DNS subdomain encoding'
    };
    return descriptions[type] || `Malicious behavior: ${type}`;
  }

  _buildDetails(incident) {
    const { package: pkg, version, threatType } = incident;
    return `The package \`${pkg}\` version \`${version}\` contains malicious code that ` +
           `performs ${this._threatDescription(threatType).toLowerCase()}. ` +
           `This was automatically detected by Sudarshana's runtime behavioral analysis ` +
           `and the package was quarantined immediately, preventing any data loss.`;
  }

  _mapSeverityCVSS(severity) {
    const map = { 'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'moderate', 'LOW': 'low' };
    return map[severity] || 'moderate';
  }

  _mapSeverityScore(severity) {
    const map = { 'CRITICAL': 9.8, 'HIGH': 8.1, 'MEDIUM': 6.5, 'LOW': 3.7 };
    return map[severity] || 6.5;
  }

  _generateCVSSVector(severity, threatType) {
    // Network attack, low complexity, no privileges, no user interaction
    if (threatType.includes('EXFIL') || threatType === 'HONEYPOT_ACCESS') {
      return 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';
    }
    return 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N';
  }

  _mapCWE(threatType) {
    const map = {
      'HONEYPOT_ACCESS': 'CWE-522',        // Insufficiently Protected Credentials
      'READ_THEN_SEND': 'CWE-200',         // Exposure of Sensitive Information
      'SENSITIVE_DATA_EXFILTRATION': 'CWE-200',
      'STAGED_EXFILTRATION': 'CWE-200',
      'CONTENT_MUTATED_SAME_VERSION': 'CWE-494', // Download of Code Without Integrity Check
      'INSTALL_SCRIPT_ATTACK': 'CWE-829',  // Inclusion of Functionality from Untrusted Control Sphere
      'DNS_TUNNELING': 'CWE-200'
    };
    return map[threatType] || 'CWE-506'; // Embedded Malicious Code
  }
}

module.exports = { AutoAdvisory };
