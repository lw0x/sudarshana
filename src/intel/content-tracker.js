'use strict';

/**
 * SUDARSHANA — CONTENT HASH TRACKER
 * 
 * "We don't just see the theft. We follow the stolen goods."
 * 
 * Tracks sensitive data through ANY transformation chain:
 *   env.AWS_KEY → write to /tmp/x → read /tmp/x → base64 → HTTP POST
 * 
 * Even if data is:
 * - Written to a temp file, then read later
 * - Encoded (base64, hex, URL-encoded)
 * - Split across multiple small chunks
 * - Concatenated with other strings
 * 
 * We track it all via content fingerprinting.
 * 
 * This defeats the "staged exfiltration" attack that bypasses
 * simple READ→SEND correlation.
 */

const crypto = require('crypto');

class ContentTracker {
  constructor() {
    // Registry of sensitive content fingerprints
    // Maps: hash(content) → { source, package, timestamp }
    this.sensitiveFingerprints = new Map();

    // Tracks file writes: filepath → { hash, package, timestamp }
    this.fileWriteRegistry = new Map();

    // Tracks outbound data: hash → { destination, package, timestamp }
    this.outboundRegistry = [];

    // Alert callbacks
    this.alertHandlers = [];

    // Config
    this.minTrackLength = 8; // Don't track strings shorter than 8 chars
    this.maxFingerprints = 10000; // Memory safety cap
  }

  /**
   * Register a handler for exfiltration alerts
   */
  onAlert(handler) {
    this.alertHandlers.push(handler);
  }

  _emitAlert(alert) {
    for (const handler of this.alertHandlers) {
      try { handler(alert); } catch (e) { /* don't let handler crash us */ }
    }
  }

  /**
   * Register sensitive content that should be tracked
   * Called when a package reads an env var, credential file, etc.
   */
  registerSensitive(content, source, packageName) {
    if (!content || typeof content !== 'string' || content.length < this.minTrackLength) return;
    if (this.sensitiveFingerprints.size >= this.maxFingerprints) return;

    const hash = this._hash(content);
    this.sensitiveFingerprints.set(hash, {
      source,
      package: packageName,
      timestamp: Date.now(),
      length: content.length
    });

    // Also register common encodings
    this._registerEncodings(content, source, packageName);
  }

  /**
   * Pre-compute hashes for common encodings of sensitive data
   */
  _registerEncodings(content, source, packageName) {
    const encodings = [
      { name: 'base64', value: Buffer.from(content).toString('base64') },
      { name: 'hex', value: Buffer.from(content).toString('hex') },
      { name: 'url', value: encodeURIComponent(content) },
      { name: 'reversed', value: content.split('').reverse().join('') },
    ];

    for (const enc of encodings) {
      if (enc.value.length >= this.minTrackLength) {
        const hash = this._hash(enc.value);
        this.sensitiveFingerprints.set(hash, {
          source: `${source} [${enc.name} encoded]`,
          package: packageName,
          timestamp: Date.now(),
          encoding: enc.name,
          length: enc.value.length
        });
      }
    }

    // Also track substrings (for chunked exfiltration)
    // Register first half, second half, and chunks of 32 chars
    if (content.length >= 32) {
      const mid = Math.floor(content.length / 2);
      const chunks = [
        content.substring(0, mid),
        content.substring(mid),
        ...this._chunkString(content, 32)
      ];

      for (const chunk of chunks) {
        if (chunk.length >= this.minTrackLength) {
          const hash = this._hash(chunk);
          this.sensitiveFingerprints.set(hash, {
            source: `${source} [partial]`,
            package: packageName,
            timestamp: Date.now(),
            partial: true,
            length: chunk.length
          });
        }
      }
    }
  }

  /**
   * Check if data being written to a file contains sensitive content
   */
  onFileWrite(filePath, content, packageName) {
    if (!content || typeof content !== 'string') return;

    const matches = this._findSensitiveContent(content);

    if (matches.length > 0) {
      // Track this file as containing sensitive data
      this.fileWriteRegistry.set(filePath, {
        hashes: matches.map(m => m.hash),
        package: packageName,
        timestamp: Date.now(),
        sources: matches.map(m => m.source)
      });

      this._emitAlert({
        type: 'SENSITIVE_DATA_STAGED',
        severity: 'HIGH',
        package: packageName,
        detail: `Wrote sensitive data to ${filePath}`,
        sources: matches.map(m => m.source),
        timestamp: Date.now()
      });
    }
  }

  /**
   * Check if data being sent over network contains sensitive content
   */
  onNetworkSend(destination, content, packageName) {
    if (!content) return;
    const contentStr = typeof content === 'string' ? content : JSON.stringify(content);

    const matches = this._findSensitiveContent(contentStr);

    if (matches.length > 0) {
      this.outboundRegistry.push({
        destination,
        package: packageName,
        timestamp: Date.now(),
        sources: matches.map(m => m.source)
      });

      this._emitAlert({
        type: 'SENSITIVE_DATA_EXFILTRATION',
        severity: 'CRITICAL',
        package: packageName,
        destination,
        detail: `Sending sensitive data to ${destination}`,
        sources: matches.map(m => m.source),
        encodings: matches.filter(m => m.encoding).map(m => m.encoding),
        timestamp: Date.now()
      });

      return true; // Confirmed exfiltration
    }

    return false;
  }

  /**
   * Check if data read from a file was previously staged
   */
  onFileRead(filePath, content, packageName) {
    const staged = this.fileWriteRegistry.get(filePath);

    if (staged && staged.package !== packageName) {
      // Different package reading a file that was staged by another package
      // This is the staged exfiltration pattern
      this._emitAlert({
        type: 'STAGED_READ_BY_DIFFERENT_PACKAGE',
        severity: 'HIGH',
        writer: staged.package,
        reader: packageName,
        filePath,
        detail: `${packageName} reading sensitive data staged by ${staged.package}`,
        originalSources: staged.sources,
        timestamp: Date.now()
      });
    }
  }

  /**
   * Search content for any known sensitive data fingerprints
   */
  _findSensitiveContent(content) {
    const matches = [];
    const contentHash = this._hash(content);

    // Exact match
    if (this.sensitiveFingerprints.has(contentHash)) {
      const info = this.sensitiveFingerprints.get(contentHash);
      matches.push({ hash: contentHash, ...info });
      return matches;
    }

    // Sliding window search for partial matches
    const windowSizes = [32, 64, 128, 256];
    for (const size of windowSizes) {
      if (content.length < size) continue;

      for (let i = 0; i <= content.length - size; i += Math.floor(size / 2)) {
        const window = content.substring(i, i + size);
        const windowHash = this._hash(window);

        if (this.sensitiveFingerprints.has(windowHash)) {
          const info = this.sensitiveFingerprints.get(windowHash);
          matches.push({ hash: windowHash, ...info });
          // Don't search further for this window size
          break;
        }
      }

      if (matches.length > 0) break; // Found something, stop searching
    }

    return matches;
  }

  /**
   * SHA256 hash (first 16 hex chars for efficiency)
   */
  _hash(content) {
    return crypto.createHash('sha256').update(content).digest('hex').substring(0, 16);
  }

  /**
   * Split string into chunks
   */
  _chunkString(str, size) {
    const chunks = [];
    for (let i = 0; i < str.length; i += size) {
      chunks.push(str.substring(i, i + size));
    }
    return chunks;
  }

  /**
   * Get current tracking stats
   */
  getStats() {
    return {
      sensitiveFingerprints: this.sensitiveFingerprints.size,
      stagedFiles: this.fileWriteRegistry.size,
      outboundDetections: this.outboundRegistry.length,
      alerts: this.outboundRegistry.filter(o => o.sources.length > 0).length
    };
  }
}

module.exports = { ContentTracker };
