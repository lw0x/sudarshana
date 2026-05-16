# Contributing to Sudarshana

Thanks for your interest in making npm supply-chain security better! 🔥

## Getting Started

```bash
git clone https://github.com/lw0x/sudarshana.git
cd sudarshana
node bin/sudarshana.js doctor   # verify everything works
```

## Project Structure

```
sudarshana/
├── bin/sudarshana.js              CLI entry point
├── src/
│   ├── index.js                   Auto-initializing entry (--require hook)
│   ├── kernel/
│   │   ├── sandbox-kernel.js      Per-package virtual module factory
│   │   ├── policy-engine.js       Zero-trust permission resolution
│   │   └── behavioral-engine.js   Correlation rules (READ→SEND detection)
│   ├── stealth/
│   │   └── stealth-loader.js      Invisible Module._load interceptor
│   ├── virtual/
│   │   └── virtual-env.js         Per-package process.env Proxy + honeypots
│   ├── cli/
│   │   ├── auto-policy.js         Auto-generates .sudarshana.json
│   │   └── smoke-test.js          Self-verification tests
│   └── utils/
│       ├── attribution.js         Call-stack based package identification
│       └── config.js              Config loader
└── test/                          Tests (help us add more!)
```

## How to Contribute

### 🐛 Bug Reports
- Run `sudarshana doctor` and include the output
- Describe what you expected vs what happened
- Include Node.js version and OS

### 🧪 Adding Tests
We need more tests! Especially:
- Real package compatibility (does express still work under sandbox?)
- Edge cases (circular requires, lazy loading, conditional imports)
- ESM module support

### 📦 Adding Package Presets
Know a popular package's minimal permissions? Add it to:
- `KNOWN_PACKAGE_POLICIES` in `src/kernel/policy-engine.js`
- `PURE_COMPUTE_PACKAGES` / `NETWORK_PACKAGES` etc. in `src/cli/auto-policy.js`

### 🔒 Security Research
Found a bypass? Please report responsibly:
1. Open a GitHub Security Advisory (private)
2. Or email: [create a security contact]

## Code Style

- Pure Node.js — zero external dependencies (intentional!)
- `'use strict'` in every file
- Descriptive variable names over comments
- Every function documents what it BLOCKS and what it ALLOWS

## Philosophy

Before submitting, ask yourself:
1. Does this make the **secure path easier** than the insecure path?
2. Does this maintain **invisibility** from sandboxed packages?
3. Does this produce **natural errors** (ENOENT, not "BLOCKED")?
4. Is the **false positive rate** still zero?

If yes to all → PR welcome! 🎯

## License

By contributing, you agree your contributions are licensed under MIT.
