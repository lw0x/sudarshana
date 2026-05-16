'use strict';

/**
 * SUDARSHANA — LEVEL 16: LLM CODE REVIEWER
 * 
 * "The disc doesn't match patterns. It UNDERSTANDS intent."
 * 
 * Feeds suspicious package source to an LLM and asks:
 * "What is this code trying to do? Is it malicious?"
 * 
 * This catches attacks that NO regex can catch:
 * - Polymorphic code (changes form every time)
 * - Novel attack vectors (never seen before)
 * - Deeply obfuscated logic (human-unreadable)
 * - Social engineering in code (looks legitimate but isn't)
 * 
 * Supports:
 * - Local LLMs (Ollama, llama.cpp) — air-gapped, no data leaves machine
 * - Cloud LLMs (Claude, GPT) — more powerful, requires API key
 * - Hybrid: local for triage, cloud for deep analysis
 * 
 * The LLM doesn't just say "malicious" — it explains WHY in plain English.
 * This makes every alert actionable, not just a red flag.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

const SYSTEM_PROMPT = `You are Sudarshana, a security analysis engine. You analyze npm package source code for malicious intent.

Your job:
1. Determine what the code DOES (not what it says it does)
2. Classify its INTENT (legitimate utility, data collection, credential theft, backdoor, etc.)
3. Rate its threat level: SAFE, SUSPICIOUS, MALICIOUS
4. Explain in plain English what a non-technical person should know

Rules:
- Obfuscated code is ALWAYS suspicious (legitimate packages don't hide their logic)
- Any code that reads credentials AND makes network requests = HIGH RISK
- eval() with external input = CRITICAL
- Be concise. No fluff. Security team reads this at 3am.`;

class LLMReviewer {
  constructor(options = {}) {
    this.provider = options.provider || 'local'; // 'local' | 'claude' | 'openai'
    this.endpoint = options.endpoint || 'http://localhost:11434/api/generate'; // Ollama default
    this.model = options.model || 'llama3';
    this.apiKey = options.apiKey || null;
    this.maxTokens = options.maxTokens || 2000;
    this.timeout = options.timeout || 30000;
  }

  /**
   * Review a package's source code using LLM
   */
  async reviewPackage(packageName, sourcePath) {
    const source = this._loadSource(sourcePath);
    if (!source) return { error: 'Could not load source' };

    const prompt = this._buildPrompt(packageName, source);
    const response = await this._query(prompt);

    return {
      package: packageName,
      timestamp: new Date().toISOString(),
      provider: this.provider,
      model: this.model,
      analysis: response,
      classification: this._extractClassification(response),
      confidence: this._extractConfidence(response)
    };
  }

  /**
   * Classify intent of a code snippet
   */
  async classifyIntent(code, context = '') {
    const prompt = `Analyze this code and classify its PRIMARY INTENT into exactly one category:

CATEGORIES:
- UTILITY: General purpose helper/tool
- DATA_COLLECTION: Gathers information about the environment
- CREDENTIAL_THEFT: Attempts to steal secrets/keys/tokens
- BACKDOOR: Provides unauthorized remote access
- CRYPTOMINER: Uses compute resources for mining
- RANSOMWARE: Encrypts or destroys data
- SPYWARE: Monitors user activity
- LEGITIMATE_NETWORK: Makes authorized network calls (e.g., API client)
- LEGITIMATE_FS: Authorized file operations (e.g., build tool)

Context: ${context}

Code:
\`\`\`javascript
${code.substring(0, 3000)}
\`\`\`

Respond with ONLY:
INTENT: <category>
CONFIDENCE: <HIGH|MEDIUM|LOW>
EXPLANATION: <one sentence>`;

    const response = await this._query(prompt);
    return this._parseIntentResponse(response);
  }

  /**
   * Generate detection rules from a confirmed malicious sample
   */
  async generateRule(maliciousCode, threatType) {
    const prompt = `You are analyzing confirmed malicious code. Generate a detection rule.

Threat type: ${threatType}
Code:
\`\`\`javascript
${maliciousCode.substring(0, 2000)}
\`\`\`

Generate a JSON detection rule with:
1. "name": short identifier
2. "description": what it catches
3. "regex": JavaScript regex pattern that would catch THIS and similar variants
4. "severity": "critical" | "high" | "medium"
5. "false_positive_risk": "low" | "medium" | "high"

Respond with ONLY valid JSON.`;

    const response = await this._query(prompt);
    try {
      return JSON.parse(response);
    } catch(e) {
      // Try to extract JSON from response
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try { return JSON.parse(jsonMatch[0]); } catch(e2) {}
      }
      return { error: 'Could not parse rule', raw: response };
    }
  }

  /**
   * Translate natural language policy to JSON config
   */
  async naturalLanguagePolicy(description) {
    const prompt = `Convert this natural language security policy into a Sudarshana JSON policy:

"${description}"

Sudarshana policy format:
{
  "<package_name>": {
    "trust_level": "trusted|limited|untrusted",
    "env_visible": ["VAR1", "VAR2"],  // or [] for none
    "fs_read": ["./path/*"],           // or [] for none
    "fs_write": [],                    // or [] for none
    "network": ["domain.com"],         // or [] for none
    "shell": []                        // or [] for none
  }
}

Respond with ONLY valid JSON. No explanation.`;

    const response = await this._query(prompt);
    try {
      return { success: true, policy: JSON.parse(response) };
    } catch(e) {
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try { return { success: true, policy: JSON.parse(jsonMatch[0]) }; } catch(e2) {}
      }
      return { success: false, raw: response };
    }
  }

  /**
   * Explain an alert in plain English (for non-technical stakeholders)
   */
  async explainAlert(alert) {
    const prompt = `Explain this security alert to a non-technical manager in 2-3 sentences:

Package: ${alert.package}
Threat: ${alert.threatType}
Details: ${JSON.stringify(alert.evidence || {})}

Be clear about:
1. What happened
2. What's at risk
3. What was done about it

No jargon. No technical terms. Plain English.`;

    return await this._query(prompt);
  }

  /**
   * Query the LLM (supports multiple providers)
   */
  async _query(prompt) {
    switch (this.provider) {
      case 'local':
        return this._queryOllama(prompt);
      case 'claude':
        return this._queryClaude(prompt);
      case 'openai':
        return this._queryOpenAI(prompt);
      default:
        return this._queryOllama(prompt);
    }
  }

  /**
   * Query local Ollama instance
   */
  _queryOllama(prompt) {
    return new Promise((resolve, reject) => {
      const url = new URL(this.endpoint);
      const payload = JSON.stringify({
        model: this.model,
        prompt: `${SYSTEM_PROMPT}\n\n${prompt}`,
        stream: false,
        options: { num_predict: this.maxTokens }
      });

      const req = http.request({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        timeout: this.timeout
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            resolve(parsed.response || parsed.message?.content || data);
          } catch(e) { resolve(data); }
        });
      });

      req.on('error', (e) => resolve(`[LLM unavailable: ${e.message}]`));
      req.on('timeout', () => { req.destroy(); resolve('[LLM timeout]'); });
      req.write(payload);
      req.end();
    });
  }

  /**
   * Query Claude API
   */
  _queryClaude(prompt) {
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify({
        model: this.model || 'claude-3-haiku-20240307',
        max_tokens: this.maxTokens,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: prompt }]
      });

      const req = https.request({
        hostname: 'api.anthropic.com',
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
          'anthropic-version': '2023-06-01'
        },
        timeout: this.timeout
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            resolve(parsed.content?.[0]?.text || data);
          } catch(e) { resolve(data); }
        });
      });

      req.on('error', (e) => resolve(`[Claude unavailable: ${e.message}]`));
      req.on('timeout', () => { req.destroy(); resolve('[Claude timeout]'); });
      req.write(payload);
      req.end();
    });
  }

  /**
   * Query OpenAI API
   */
  _queryOpenAI(prompt) {
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify({
        model: this.model || 'gpt-4o-mini',
        max_tokens: this.maxTokens,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: prompt }
        ]
      });

      const req = https.request({
        hostname: 'api.openai.com',
        path: '/v1/chat/completions',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`
        },
        timeout: this.timeout
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            resolve(parsed.choices?.[0]?.message?.content || data);
          } catch(e) { resolve(data); }
        });
      });

      req.on('error', (e) => resolve(`[OpenAI unavailable: ${e.message}]`));
      req.on('timeout', () => { req.destroy(); resolve('[OpenAI timeout]'); });
      req.write(payload);
      req.end();
    });
  }

  _loadSource(sourcePath) {
    try {
      if (fs.statSync(sourcePath).isDirectory()) {
        // Load main file + first few JS files
        const files = fs.readdirSync(sourcePath)
          .filter(f => f.endsWith('.js'))
          .slice(0, 3);
        return files.map(f => fs.readFileSync(path.join(sourcePath, f), 'utf8')).join('\n\n');
      }
      return fs.readFileSync(sourcePath, 'utf8');
    } catch(e) { return null; }
  }

  _buildPrompt(packageName, source) {
    return `Analyze this npm package for malicious behavior:

Package: ${packageName}
Source code:
\`\`\`javascript
${source.substring(0, 4000)}
\`\`\`

Provide:
1. CLASSIFICATION: SAFE | SUSPICIOUS | MALICIOUS
2. INTENT: What is this code trying to do?
3. RISK FACTORS: List specific concerns
4. RECOMMENDATION: What should the developer do?`;
  }

  _extractClassification(response) {
    if (/MALICIOUS/i.test(response)) return 'MALICIOUS';
    if (/SUSPICIOUS/i.test(response)) return 'SUSPICIOUS';
    return 'SAFE';
  }

  _extractConfidence(response) {
    if (/HIGH\s*CONFIDENCE|CERTAINLY|CLEARLY/i.test(response)) return 'HIGH';
    if (/LOW\s*CONFIDENCE|UNCERTAIN|POSSIBLY/i.test(response)) return 'LOW';
    return 'MEDIUM';
  }

  _parseIntentResponse(response) {
    const intentMatch = response.match(/INTENT:\s*(\w+)/i);
    const confMatch = response.match(/CONFIDENCE:\s*(\w+)/i);
    const explMatch = response.match(/EXPLANATION:\s*(.+)/i);

    return {
      intent: intentMatch ? intentMatch[1] : 'UNKNOWN',
      confidence: confMatch ? confMatch[1] : 'MEDIUM',
      explanation: explMatch ? explMatch[1] : response.substring(0, 200)
    };
  }
}

module.exports = { LLMReviewer, SYSTEM_PROMPT };
