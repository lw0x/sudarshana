# Sudarshana

**Your npm packages are running with your credentials. All of them. Right now.**

Every `node_modules/` dependency gets full access to your env vars, your filesystem, your network. That one package with 3 weekly downloads that your ORM depends on? It can read your AWS keys and POST them anywhere. And you'd never know.

Sudarshana fixes this. Per-package. Invisible. Zero config.

---

## What it does

Sudarshana wraps every package in an invisible sandbox. Each package only sees what it *needs* — nothing more.

- **lodash** sees: nothing. Pure compute. No env, no fs, no network.
- **express** sees: `PORT`, `NODE_ENV`, its own files, localhost binding.
- **axios** sees: only the domains you declared in your config.
- **evil-pkg** sees: fake credentials that trigger an alert the moment it touches them.

Packages can't detect they're sandboxed. Blocked operations return natural errors (`ENOENT`, `ENOTFOUND`) — not "PERMISSION DENIED" flags that tip off attackers.

---

## Quick start

```bash
npx sudarshana init          # scans your project, generates policies
npx sudarshana doctor        # checks everything works
npx sudarshana run -- node app.js   # runs your app, sandboxed
```

Or let it learn what's normal first:

```bash
npx sudarshana learn -- node app.js   # observe for a few runs
npx sudarshana learn --generate       # outputs tightest possible policy
```

That's it. No code changes. No config files to maintain.

---

## Commands

| Command | What it does |
|---------|-------------|
| `sudarshana init` | Auto-generates per-package policies from your dependency graph |
| `sudarshana run` | Runs your app with invisible per-package sandboxing |
| `sudarshana learn` | Observes behavior → auto-writes the tightest possible policy |
| `sudarshana scan` | Static analysis — catches eval, obfuscation, encoded payloads |
| `sudarshana dna` | Behavioral DNA — flags any mutation in package behavior |
| `sudarshana drift` | Detects when packages gain new capabilities between versions |
| `sudarshana snapshot` | Saves behavioral baseline for future comparison |
| `sudarshana predict` | Transitive risk, anomaly detection, pre-merge simulation |
| `sudarshana map` | Interactive dark-theme HTML showing your attack surface |
| `sudarshana dashboard` | Real-time local web UI (localhost:4040) |
| `sudarshana sbom` | CycloneDX SBOM with per-package capability annotations |
| `sudarshana compliance` | Maps your posture to ISO 27001 / SOC 2 / NIST CSF |
| `sudarshana forensics` | Full incident timeline for your IR team |
| `sudarshana heal` | Self-healing — auto-tightens unused, auto-relaxes false positives |
| `sudarshana network` | P2P anonymous threat sharing between Sudarshana instances |
| `sudarshana install` | npm install with postinstall script isolation |
| `sudarshana audit` | Package integrity verification |
| `sudarshana doctor` | Self-test (verifies core mechanisms work) |

---

## How it works (30 seconds)

1. **Intercepts `require()` and `import`** — every module load goes through Sudarshana
2. **Identifies the caller** — call-stack attribution knows which *package* is asking
3. **Applies per-package policy** — each package gets a virtual environment tailored to its needs
4. **Monitors behavior** — if a package reads credentials then makes a network call, that's flagged
5. **Plants honeypots** — fake credential values that trigger alerts if accessed
6. **Tracks content** — follows sensitive data through encoding, temp files, chunking
7. **Self-heals** — unused permissions get removed, false positives get auto-relaxed

All of this happens in ~2ms overhead per require call. Your app runs at normal speed.

---

## The attacks it stops

| Attack | Real-world example | How Sudarshana stops it |
|--------|-------------------|------------------------|
| Credential theft | `event-stream` (2018) | Package can't see real env vars — only honeypots |
| Data exfiltration | `@azure/identity` theft (2023) | Network blocked to undeclared domains |
| Staged exfiltration | Write to tmp → read → send | Content hash tracked across all transformations |
| Filesystem snooping | `node-ipc` protest-ware (2022) | Can't write outside its own directory |
| Cryptomining | `ua-parser-js` hijack (2021) | Shell execution blocked |
| Supply chain pivot | Ledger Connect Kit (2023) | DNS resolution fails for attacker domains |
| Maintainer takeover | Any future attack | Behavioral DNA detects mutation instantly |
| Zero-day | Unknown | If behavior changes, it's flagged — no signature needed |

---

## Architecture

```
L10  🧠 AUTONOMOUS     Self-healing, behavioral DNA, incident response
L9   🌐 ECOSYSTEM      Dashboard, P2P threat network, GitHub Action
L8   🧠 PREDICTIVE     Anomaly detection, transitive risk, pre-merge sim
L7   📜 COMPLIANCE     SBOM, forensics, ISO/SOC2/NIST mapping
L6   🔬 SCANNER        AST analysis, obfuscation scoring, entropy
L5   📊 VISIBILITY     Interactive force-directed security map
L4   🛡️  DEFENSE        Quarantine, drift detection, threat feed
L3   🧠 SELF-LEARN     Auto-policy, reputation scoring, learn mode
L2   🔥 BEHAVIORAL     Honeypots, content tracking, READ→SEND correlation
L1   🏗️  SANDBOX        Per-package isolation, invisible, natural errors
```

---

## Zero config

Run `sudarshana init` and it figures out your dependency graph. It knows that:
- `lodash`, `ramda`, `underscore` → pure compute, need nothing
- `express`, `fastify`, `koa` → need PORT and localhost binding
- `pg`, `mysql2`, `prisma` → need DATABASE_URL and db host
- `aws-sdk`, `@aws-sdk/*` → need AWS_* vars and *.amazonaws.com

Or run `sudarshana learn` for a week — it observes and generates the tightest policy automatically. Zero manual config ever.

---

## Philosophy

Named after the Sudarshana Chakra — the divine disc that protects by *cutting off* threats, not by watching them happen.

Most security tools are Bheeshma — wise observers who see everything but intervene too late. Sudarshana is different. It doesn't detect attacks. It makes them *physically impossible*. A package can't exfiltrate credentials it literally cannot see.

---

## Requirements

- Node.js >= 16
- Works on Linux, macOS, Windows
- Zero external dependencies (intentional — we practice what we preach)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We especially need help with:

- More package presets
- Edge case discovery
- Evasion research

---

## Credits

```
Conceived and forged by lw0x × bb1nfosec

"The disc doesn't warn. It severs."
```

---

## License

MIT
