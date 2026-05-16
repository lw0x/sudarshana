# Sudarshana

**Your npm packages are running with your credentials. All of them. Right now.**

Every `node_modules/` dependency gets full access to your env vars, your filesystem, your network. That one package with 3 weekly downloads that your ORM depends on? It can read your AWS keys and POST them anywhere. And you'd never know.

Sudarshana fixes this. Per-package. Invisible. Zero config. Zero dependencies.

```
54 files │ 552 KB │ 34 commands │ 0 dependencies │ 20 levels │ 6 ecosystems
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

Or predict the future:

```bash
npx sudarshana precognition          # which packages will be attacked next?
```

---

## What happens under Sudarshana

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

No "BLOCKED" errors. Just a universe where the things they're looking for don't exist.

---

## Architecture

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │   L20  ∞²  ABSOLUTE                                         │
    │        Precognition — attacker economics modeling,           │
    │        maintainer burnout prediction, blast radius,          │
    │        attack vector evolution forecasting (through 2028+)   │
    │                                                              │
    │   L19  👑  SOVEREIGNTY                                       │
    │        Certification authority (Bronze→Diamond),             │
    │        cryptographically signed trust badges                 │
    │                                                              │
    │   L18  🌱  GENESIS                                           │
    │        Dependency elimination — replace risky deps           │
    │        with safe inlines, zero deps = zero risk              │
    │                                                              │
    │   L17  👁️🗨️ OMNIPRESENCE                                      │
    │        System agent daemon, git pre-commit hooks,            │
    │        shell integration, OS-native notifications            │
    │                                                              │
    │   L16  💭  CONSCIOUSNESS                                     │
    │        LLM code reviewer, intent classification,             │
    │        natural language policies, autonomous rules            │
    │                                                              │
    │   L15  ∞   TRANSCENDENCE                                     │
    │        Registry proxy (scan-before-install),                 │
    │        polyglot (npm/PyPI/Gems/Go/Rust/Maven),              │
    │        global immune system with antibodies                  │
    │                                                              │
    │   L14  ⏳  TEMPORAL                                          │
    │        Pre-crime prediction, digital twin,                   │
    │        regression oracle, time-travel audit                  │
    │                                                              │
    │   L13  ⚛️  SINGULARITY                                       │
    │        Custom runtime (VM-isolated contexts),                │
    │        kernel-level policies (eBPF/seccomp/AppArmor)         │
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
    │        autonomous incident response (0-second)               │
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

## All 34 commands

| Command | What it does |
|---------|-------------|
| **Core** | |
| `sudarshana init` | Auto-generate per-package policies |
| `sudarshana run` | Run app with invisible sandboxing |
| `sudarshana learn` | Observe → auto-write tightest policy |
| `sudarshana doctor` | Self-test core mechanisms |
| **Analysis** | |
| `sudarshana scan` | Static AST + entropy + obfuscation scoring |
| `sudarshana dna` | Behavioral DNA — flag any mutation |
| `sudarshana drift` | Detect capability changes between versions |
| `sudarshana predict` | Transitive risk + anomaly detection |
| `sudarshana watch` | Registry monitoring — typosquats, time-bombs |
| `sudarshana precrime` | Predict which packages WILL be compromised |
| **Visualization** | |
| `sudarshana map` | Interactive dark-theme attack surface graph |
| `sudarshana dashboard` | Real-time local web UI |
| **Defense** | |
| `sudarshana snapshot` | Save behavioral baseline |
| `sudarshana heal` | Self-healing policies (auto-tighten/relax) |
| `sudarshana install` | npm install with postinstall isolation |
| `sudarshana audit` | Package integrity verification |
| `sudarshana kernel` | Generate eBPF/seccomp/AppArmor OS policies |
| `sudarshana eliminate` | Replace risky deps with safe inlines |
| **Intelligence** | |
| `sudarshana intel` | Attacker profiles built from caught threats |
| `sudarshana decoy` | Generate honeypot packages to trap attackers |
| `sudarshana network` | P2P anonymous threat sharing |
| `sudarshana immune` | Global immune system + antibodies |
| **Compliance** | |
| `sudarshana sbom` | CycloneDX SBOM with capability annotations |
| `sudarshana compliance` | ISO 27001 / SOC 2 / NIST CSF mapping |
| `sudarshana forensics` | Full incident timeline for IR teams |
| `sudarshana certify` | Issue trust certificates (🥉→💎) |
| **Omniscience** | |
| `sudarshana simulate` | Red-team yourself — 16 attack scenarios |
| `sudarshana attest` | Cryptographic supply chain provenance |
| `sudarshana advisory` | Auto-generate CVE/GHSA/npm reports |
| **Temporal** | |
| `sudarshana twin` | Digital twin — regression oracle + time-travel |
| `sudarshana precognition` | Predict future attack vectors (2026-2028+) |
| **Platform** | |
| `sudarshana proxy` | Local registry proxy (scan-before-install) |
| `sudarshana polyglot` | Multi-ecosystem (npm/PyPI/Gems/Go/Rust/Maven) |
| `sudarshana agent` | System-wide background protection daemon |

---

## Attacks it stops

| Attack | How |
|--------|-----|
| Credential theft | Env vars don't exist for that package |
| Data exfiltration | Network blocked — ECONNREFUSED |
| Staged exfiltration | Content hash tracked across transforms |
| Filesystem snooping | Files don't exist — ENOENT |
| Cryptomining | Shell blocked — spawn ENOENT |
| Supply chain pivot | DNS returns ENOTFOUND |
| Maintainer takeover | Behavioral DNA catches mutation |
| Time-bomb (delayed) | Static scanner + pre-crime detects patterns |
| Zero-day (unknown) | Behavior changed = flagged. No signature needed. |
| Typosquatting | Registry watcher + decoy traps |
| Native addon bypass | Kernel policies (seccomp/eBPF) enforce at OS level |
| Future compromise | Pre-crime + precognition predicts what's next |
| Polymorphic malware | LLM reviewer understands INTENT, not patterns |
| Build-tool poisoning | Predicted as next-gen vector — defenses pre-built |

---

## How it compares

```
                              Snyk    Socket   Bheeshma   Sudarshana
                              ($$$)   ($$)     (free)     (free)
─────────────────────────────────────────────────────────────────────
Runtime per-package sandbox     ❌      ❌       ❌         ✅
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
Kernel-level policies           ❌      ❌       ❌         ✅
Pre-crime prediction            ❌      ❌       ❌         ✅
Digital twin / time-travel      ❌      ❌       ❌         ✅
Custom VM runtime               ❌      ❌       ❌         ✅
LLM intent analysis             ❌      ❌       ❌         ✅
System-wide agent               ❌      ❌       ❌         ✅
Dependency elimination          ❌      ❌       ❌         ✅
Certification authority         ❌      ❌       ❌         ✅
Immune system (antibodies)      ❌      ❌       ❌         ✅
Registry proxy                  ❌      ❌       ❌         ✅
Multi-ecosystem (6 langs)       partial ❌       ❌         ✅
Precognition (future vectors)   ❌      ❌       ❌         ✅
Static scanning                 ✅      ✅       ❌         ✅
SBOM generation                 ✅      ❌       ❌         ✅
Registry watching               ❌      ✅       ❌         ✅
Compliance mapping              $$$     ❌       ❌         ✅
Dashboard                       $$$     ❌       ❌         ✅
P2P threat sharing              ❌      ❌       ❌         ✅
Zero dependencies               ❌      ❌       ❌         ✅
─────────────────────────────────────────────────────────────────────
Score                           4/31   3/31     0/31       31/31
```

---

## Philosophy

Named after the Sudarshana Chakra — the divine disc that doesn't warn, doesn't negotiate, doesn't wait. It severs.

Most security tools observe. They watch the theft happen and write a report. Sudarshana makes theft *physically impossible*. A package can't exfiltrate credentials it cannot see. Can't phone home to a domain that doesn't resolve. Can't read a file that doesn't exist in its universe.

When something mutates — the disc doesn't need a signature. Behavior changed. That's enough.

When something will be attacked — the disc sees it coming. Attacker economics don't lie.

The disc exists beyond time, beyond language, beyond identity. It is the immune system of all software that will ever be written.

---

## Requirements

- Node.js >= 16
- Works on Linux, macOS, Windows
- Zero external dependencies
- Kernel policies (L13): Linux 5.x+ for eBPF
- LLM features (L16): Ollama (local) or Claude/OpenAI API key
- System agent (L17): Runs as background daemon

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
