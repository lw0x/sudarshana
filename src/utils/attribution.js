'use strict';

/**
 * Attribution Engine — Resolves stack traces to originating packages
 */

const path = require('path');

class Attribution {
  constructor() {
    this.cache = new Map();
  }

  /**
   * Resolve a stack trace to the originating npm package
   * @param {string} stack - Error().stack string
   * @returns {string} Package name or 'app' for application code
   */
  resolve(stack) {
    if (!stack) return 'unknown';

    // Cache lookup
    const cacheKey = stack.substring(0, 200);
    if (this.cache.has(cacheKey)) return this.cache.get(cacheKey);

    const lines = stack.split('\n');
    let result = 'app';

    // Walk the stack from outermost to find the first node_modules reference
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      const match = line.match(/node_modules[/\\](@[^/\\]+[/\\][^/\\]+|[^/\\]+)/);
      if (match) {
        result = match[1];
        break;
      }
    }

    this.cache.set(cacheKey, result);
    return result;
  }
}

module.exports = Attribution;
