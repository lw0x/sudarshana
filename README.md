# Sudarshana

**Your npm packages are running with your credentials. All of them. Right now.**

Every `node_modules/` dependency gets full access to your env vars, your filesystem, your network. That one package with 3 weekly downloads that your ORM depends on? It can read your AWS keys and POST them anywhere. And you'd never know.

Sudarshana fixes this. Per-package. Invisible. Zero config. Zero dependencies.

```
46 files │ 455 KB │ 27 commands │ 0 dependencies │ 14 architectural levels
```

---

## Quick start

```bash
npx sudarshana init              # auto-generates per-package policies
npx sudarshana run -- node app.js  # sandboxed. invisible. done.
```

Or let it learn:

```bash
npx sudarshana learn -- node app.js   # observe
npx sudarshana learn --generate       # write tightest possible policy
```

That's it. No code changes. No manual config.

---

## What happens when evil-pkg runs under Sudarshana

```
┌─────────────────────────────────────────────────────────────┐
│  evil-pkg tries:              │  What it gets:               │
├───────────────────────────────┼──────────────────────────────┤
│  process.env.AWS_SECRET_KEY   │  undefined (doesn't exist)   │
│  fs.readFile('/etc/passwd')   │  ENOENT (file not found)     │
│  dns.resolve('evil.com')      │  ENOTFOUND (domain unknown)  │
│  http.request('evil.com')     │  ECONNREFUSED (natural)      │
│  child_process.exec('curl')   │  spawn ENOENT (cmd missing)  │
│  process.env.DATABASE_URL     │  🍯 HONEYPOT → ALERT FIRED  │
├───────────────────────────────┼──────────────────────────────┤
│  Meanwhile, express:          │                              │
│  process.env.PORT             │  "3000" ✅ (works normally)  │
│  fs.readFile('./views/x.ejs') │  file content ✅             │
│  net.listen(3000)             │  listening ✅                │
└─────────────────────────────────────────────────────────────┘
```

Packages can't detect they're sandboxed. No "BLOCKED" errors. Just a universe where the things they're looking for don't exist.

---

## Architecture

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │   L14  ⏳  TEMPORAL                                          │
    │        Pre-crime prediction, digital twin,                   │
    │        regression oracle, time-travel audit                  │
    │                                                              │
    │   L13  ⚛️  SINGULARITY                                       │
    │        Custom runtime (VM contexts), kernel-level            │
    │        policies (eBPF/seccomp/AppArmor)                      │
    │                                                              │
    │   L12  👁️  OMNISCIENCE                                       │
    │        Ecosystem behavioral DB, attack simulation,           │
    │        supply chain provenance, auto-CVE/advisory            │
    │                                                              │
    │   L11  ⚔️  OFFENSIVE                                         │
    │        Decoy packages, attacker fingerprinting,              │
    │        registry watcher, time-bomb detection                 │
    │                                                              │
    │   L10  🧠  AUTONOMOUS                                        │
    │        Self-healing policies, behavioral DNA,                │
    │        autonomous incident response                          │
    │                                                              │
    │   L9   🌐  ECOSYSTEM                                         │
    │        Real-time dashboard, P2P threat network,              │
    │        GitHub Action CI/CD                                   │
    │                                                              │
    │   L8   📡  PREDICTIVE                                        │
    │        Z-score anomaly detection, transitive risk,           │
    │        maintainer trust chain, pre-merge simulation          │
    │                                                              │
    │   L7   📜  COMPLIANCE                                        │
    │        CycloneDX SBOM, forensics timeline,                   │
    │        ISO 27001 / SOC 2 / NIST CSF mapping                  │
    │                                                              │
    │   L6   🔬  SCANNER                                           │
    │        AST analysis, Shannon entropy, obfuscation score,     │
    │        install script simulation                              │
    │                                                              │
    │   L5   📊  VISIBILITY                                        │
    │        Interactive force-directed dependency map,             │
    │        dark-theme HTML, click-to-inspect                     │
    │                                                              │
    │   L4   🛡️   DEFENSE                                          │
    │        Quarantine (no crash), drift detection,               │
    │        shared threat intelligence feed                       │
    │                                                              │
    │   L3   🧠  SELF-LEARN                                        │
    │        Auto-policy generation, package reputation,           │
    │        behavioral learning across runs                       │
    │                                                              │
    │   L2   🔥  BEHAVIORAL                                        │
    │        Honeypot traps, READ→SEND correlation,                │
    │        content hash tracking across encodings                │
    │                                                              │
    │   L1   🏗️   SANDBOX                                          │
    │        Per-package Module._load isolation,                   │
    │        virtual fs/dns/http/env/shell, invisible              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## All 27 commands

| Command | What it does |
|---------|-------------|
| **Core** | |
| `sudarshana init` | Auto-generate per-package policies from dependency graph |
| `sudarshana run` | Run app with invisible per-package sandboxing |
| `sudarshana learn` | Observe behavior → auto-write tightest possible policy |
| `sudarshana doctor` | Self-test (verify core mechanisms work) |
| **Analysis** | |
| `sudarshana scan` | Static AST analysis — eval, obfuscation, encoded payloads |
| `sudarshana dna` | Behavioral DNA — flag any mutation in package behavior |
| `sudarshana drift` | Detect capability changes between versions |
| `sudarshana predict` | Transitive risk + anomaly detection + pre-merge sim |
| `sudarshana watch` | Registry monitoring — typosquats, maintainer changes, time-bombs |
| `sudarshana precrime` | Predict which packages WILL be compromised (before it happens) |
| **Visualization** | |
| `sudarshana map` | Interactive dark-theme HTML attack surface graph |
| `sudarshana dashboard` | Real-time local web UI (auto-refreshing) |
| **Defense** | |
| `sudarshana snapshot` | Save behavioral baseline |
| `sudarshana heal` | Self-healing — auto-tighten unused, auto-relax false positives |
| `sudarshana install` | npm install with postinstall isolation |
| `sudarshana audit` | Package integrity verification |
| `sudarshana kernel` | Generate eBPF/seccomp/AppArmor OS-level policies |
| **Intelligence** | |
| `sudarshana intel` | Show attacker profiles (built from caught threats) |
| `sudarshana decoy` | Generate honeypot packages to trap attackers |
| `sudarshana network` | P2P anonymous threat sharing status |
| **Compliance** | |
| `sudarshana sbom` | CycloneDX SBOM with capability annotations |
| `sudarshana compliance` | ISO 27001 / SOC 2 / NIST CSF control mapping |
| `sudarshana forensics` | Full incident timeline for IR teams |
| **Omniscience** | |
| `sudarshana simulate` | Red-team yourself — 16 attack scenarios auto-tested |
| `sudarshana attest` | Cryptographic supply chain provenance (SLSA-style) |
| `sudarshana advisory` | Auto-generate CVE/GHSA/npm reports on confirmed threats |
| **Temporal** | |
| `sudarshana twin` | Digital twin — regression oracle + time-travel audit |

---

## Attacks it stops

| Attack | Real-world example | How |
|--------|-------------------|-----|
| Credential theft | `event-stream` (2018) | Env vars don't exist for that package |
| Data exfiltration | `@azure/identity` (2023) | Network blocked — ECONNREFUSED |
| Staged exfiltration | write→encode→send | Content hash tracked across transforms |
| Filesystem snooping | `node-ipc` (2022) | Files don't exist — ENOENT |
| Cryptomining | `ua-parser-js` (2021) | Shell blocked — spawn ENOENT |
| Supply chain pivot | Ledger Connect Kit (2023) | DNS returns ENOTFOUND |
| Maintainer takeover | (any future) | Behavioral DNA catches mutation |
| Time-bomb (delayed) | Conditional trigger | Static scanner + pre-crime detects patterns |
| Zero-day (unknown) | (any future) | Behavior changed = flagged. No signature needed. |
| Typosquatting | `expresss` | Registry watcher alerts on similar names |
| Native addon bypass | C++ level attack | Kernel policies (seccomp/eBPF) enforce at OS level |
| Future compromise | (hasn't happened yet) | Pre-crime scores predict which packages are next |

---

## How it compares

```
                              Snyk    Socket   Bheeshma   Sudarshana
                              ($$$)   ($$)     (free)     (free)
─────────────────────────────────────────────────────────────────────
Runtime sandbox                 ❌      ❌       ❌         ✅
Per-package isolation           ❌      ❌       ❌         ✅
Invisible to packages           ❌      ❌       ❌         ✅
Honeypot traps                  ❌      ❌       ❌         ✅
Self-learning policies          ❌      ❌       ❌         ✅
Behavioral DNA                  ❌      ❌       ❌         ✅
Self-healing                    ❌      ❌       ❌         ✅
Quarantine (no crash)           ❌      ❌       ❌         ✅
Attack simulation               ❌      ❌       ❌         ✅
Provenance attestation          ❌      ❌       ❌         ✅
Auto CVE/advisory               ❌      ❌       ❌         ✅
Decoy packages                  ❌      ❌       ❌         ✅
Attacker profiling              ❌      ❌       ❌         ✅
Time-bomb detection             ❌      partial  ❌         ✅
Registry watching               ❌      ✅       ❌         ✅
Static scanning                 ✅      ✅       ❌         ✅
SBOM generation                 ✅      ❌       ❌         ✅
Compliance mapping              $$$     ❌       ❌         ✅
Dashboard                       $$$     ❌       ❌         ✅
P2P threat sharing              ❌      ❌       ❌         ✅
Kernel-level policies           ❌      ❌       ❌         ✅
Pre-crime prediction            ❌      ❌       ❌         ✅
Digital twin / time-travel      ❌      ❌       ❌         ✅
Custom runtime (VM sandbox)     ❌      ❌       ❌         ✅
Zero dependencies               ❌      ❌       ❌         ✅
─────────────────────────────────────────────────────────────────────
Score                           3/25   3/25     0/25       25/25
```

---

## Philosophy

Named after the Sudarshana Chakra — the divine disc that doesn't warn, doesn't negotiate, doesn't wait. It severs.

Most security tools are observers. They watch the theft happen and write a report. Sudarshana makes theft *physically impossible*. A package can't exfiltrate credentials it cannot see. Can't phone home to a domain that doesn't resolve. Can't read a file that doesn't exist in its universe.

And when something mutates — when a trusted package suddenly reaches for things it never reached for before — the disc doesn't need a signature database. It doesn't need a rule. Behavior changed. That's enough.

The disc exists across all time. It sees what was. What is. What will be.

---

## Requirements

- Node.js >= 16
- Works on Linux, macOS, Windows
- Zero external dependencies
- Kernel policies (L13): Linux 5.x+ for eBPF, any OS for Docker seccomp

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
