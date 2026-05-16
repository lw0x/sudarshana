<p align="center">
  <br>
  <img src="logo.png" alt="Sudarshana Chakra" width="280">
  <br><br>
  <strong style="font-size: 2em;">S U D A R S H A N A</strong>
  <br><br>
  <em>every package thinks it's alone. it is.</em>
  <br>
  <br>
  <code>60 files │ 660 KB │ 41 commands │ 0 dependencies │ 20 levels</code>
  <br>
  <br>
</p>

---

<br>

> **Your npm packages are running with your credentials. All of them. Right now.**
>
> That one package with 3 weekly downloads that your ORM depends on? It can read your AWS keys and POST them anywhere. And you'd never know.
>
> Sudarshana makes theft *physically impossible*. Not detected. Not blocked. **Impossible.**

<br>

---

## ⚡ 3 seconds to protect your app

```bash
npx sudarshana init              # auto-generates per-package policies
npx sudarshana run -- node app.js  # sandboxed. invisible. done.
```

That's it. No code changes. No config files. No learning curve.

---

## 🎭 What evil-pkg sees vs what express sees

```
         ╭─────────────── evil-pkg's universe ───────────────╮
         │                                                    │
         │   process.env.AWS_KEY      →  undefined            │
         │   fs.readFile('/etc/passwd') →  ENOENT             │
         │   dns.resolve('evil.com')   →  ENOTFOUND           │
         │   http.request('c2.io')     →  ECONNREFUSED        │
         │   exec('curl ...')          →  spawn ENOENT         │
         │   process.env.DB_PASSWORD   →  🍯 HONEYPOT ALERT   │
         │                                                    │
         │   It tried everything. Got nothing.                │
         │   It doesn't know it's sandboxed.                  │
         │   The errors look natural.                         │
         │                                                    │
         ╰────────────────────────────────────────────────────╯

         ╭─────────────── express's universe ────────────────╮
         │                                                    │
         │   process.env.PORT          →  "3000" ✅           │
         │   fs.readFile('./views/..') →  file content ✅     │
         │   net.listen(3000)          →  listening ✅        │
         │                                                    │
         │   Everything works. As if Sudarshana isn't there.  │
         │                                                    │
         ╰────────────────────────────────────────────────────╯
```

> The disc doesn't block. It erases. The thing you're looking for **was never there.**

---

## 🏗️ 20 Levels Deep

<details>
<summary><strong>Click to see the full architecture tower</strong></summary>

```
 ╔══════════════════════════════════════════════════════════════════╗
 ║                                                                  ║
 ║   L20  ∞²  ABSOLUTE                                             ║
 ║        Precognition — predict attacks before they're invented    ║
 ║                                                                  ║
 ║   L19  👑  SOVEREIGNTY                                           ║
 ║        Certification authority (Bronze → Diamond trust badges)   ║
 ║                                                                  ║
 ║   L18  🌱  GENESIS                                               ║
 ║        Dependency elimination — replace deps with safe inlines   ║
 ║                                                                  ║
 ║   L17  👁️  OMNIPRESENCE                                          ║
 ║        System agent daemon — protects every project on machine   ║
 ║                                                                  ║
 ║   L16  💭  CONSCIOUSNESS                                         ║
 ║        LLM code reviewer — understands intent, not patterns      ║
 ║                                                                  ║
 ║   L15  ∞   TRANSCENDENCE                                         ║
 ║        Registry proxy + polyglot (6 langs) + immune system       ║
 ║                                                                  ║
 ║   L14  ⏳  TEMPORAL                                               ║
 ║        Pre-crime + digital twin + time-travel audit              ║
 ║                                                                  ║
 ║   L13  ⚛️  SINGULARITY                                           ║
 ║        Custom runtime (VM contexts) + kernel policies            ║
 ║                                                                  ║
 ║   L12  👁️  OMNISCIENCE                                           ║
 ║        Attack simulation + provenance + auto-CVE filing          ║
 ║                                                                  ║
 ║   L11  ⚔️  OFFENSIVE                                             ║
 ║        Decoy packages + attacker fingerprinting                  ║
 ║                                                                  ║
 ║   L10  🧠  AUTONOMOUS                                            ║
 ║        Self-healing + behavioral DNA + incident response         ║
 ║                                                                  ║
 ║   L9   🌐  ECOSYSTEM                                             ║
 ║        Dashboard + P2P threat network + GitHub Action            ║
 ║                                                                  ║
 ║   L8   📡  PREDICTIVE                                            ║
 ║        Anomaly detection + transitive risk + pre-merge sim       ║
 ║                                                                  ║
 ║   L7   📜  COMPLIANCE                                            ║
 ║        SBOM + forensics + ISO/SOC2/NIST mapping                  ║
 ║                                                                  ║
 ║   L6   🔬  SCANNER                                               ║
 ║        AST + entropy + obfuscation scoring                       ║
 ║                                                                  ║
 ║   L5   📊  VISIBILITY                                            ║
 ║        Interactive force-directed security map                   ║
 ║                                                                  ║
 ║   L4   🛡️  DEFENSE                                               ║
 ║        Quarantine (no crash) + drift detection                   ║
 ║                                                                  ║
 ║   L3   🧠  SELF-LEARN                                            ║
 ║        Auto-policy + learn mode + reputation scoring             ║
 ║                                                                  ║
 ║   L2   🔥  BEHAVIORAL                                            ║
 ║        Honeypots + READ→SEND correlation + content tracking      ║
 ║                                                                  ║
 ║   L1   🏗️  SANDBOX                                               ║
 ║        Per-package isolation — invisible — natural errors        ║
 ║                                                                  ║
 ╚══════════════════════════════════════════════════════════════════╝
```

</details>

---

## 🧠 It learns. It heals. It predicts.

```bash
sudarshana learn -- node app.js     # watches what's normal
sudarshana learn --generate         # writes the tightest policy possible

sudarshana heal                     # removes permissions nobody uses
                                    # adds permissions that keep getting blocked
                                    # zero maintenance. forever.

sudarshana precognition             # "which of my packages will be attacked next?"
                                    # models attacker economics, maintainer burnout,
                                    # blast radius. sees the future.
```

---

## ⚔️ It doesn't just defend. It hunts.

```bash
sudarshana decoy --generate         # publishes honeypot packages to npm
                                    # attacker installs one → fingerprinted forever

sudarshana intel                    # shows attacker profiles built from caught threats
                                    # timing patterns, encoding style, C2 structure

sudarshana watch --timebombs        # scans your deps for if(Date.now() > X) triggers
```

---

## 📋 41 commands. 0 dependencies.

<details>
<summary><strong>Full command list</strong></summary>

| Command | What it does |
|---------|-------------|
| `init` | Auto-generate per-package policies |
| `run` | Run app with invisible sandboxing |
| `learn` | Observe → auto-write tightest policy |
| `doctor` | Self-test core mechanisms |
| `scan` | Static AST + entropy + obfuscation |
| `dna` | Behavioral DNA — flag mutations |
| `drift` | Detect capability changes between versions |
| `predict` | Transitive risk + anomaly detection |
| `watch` | Registry monitoring + time-bomb detection |
| `precrime` | Predict future compromises |
| `map` | Interactive dark-theme attack surface |
| `dashboard` | Real-time local web UI |
| `snapshot` | Save behavioral baseline |
| `heal` | Self-healing policies |
| `install` | npm install with isolation |
| `audit` | Integrity verification |
| `kernel` | Generate eBPF/seccomp OS policies |
| `eliminate` | Replace deps with safe inlines |
| `intel` | Attacker profiles |
| `decoy` | Honeypot package generation |
| `network` | P2P threat sharing |
| `immune` | Global immune system |
| `sbom` | CycloneDX SBOM |
| `compliance` | ISO 27001 / SOC 2 / NIST |
| `forensics` | Incident timeline |
| `certify` | Trust certificates (🥉→💎) |
| `simulate` | Red-team yourself (16 scenarios) |
| `attest` | Cryptographic provenance |
| `advisory` | Auto-generate CVE reports |
| `twin` | Digital twin + time-travel |
| `precognition` | Future attack vector prediction |
| `proxy` | Registry proxy (scan-before-install) |
| `polyglot` | 6 ecosystems (npm/PyPI/Go/Rust/Ruby/Java) |
| `agent` | System-wide background daemon |
| `eject` | Instant disable (emergency) |
| `enable` | Re-enable after eject |
| `debug` | "Why was my package blocked?" |
| `env` | Show detected environment + strategy |
| `vuln` | CVE scanning (free, via OSV.dev) |
| `license` | License audit + copyleft detection |
| `graph` | Full transitive dependency analysis |

</details>

---

## 🛡️ What it stops

| Attack | How |
|--------|-----|
| Credential theft | env vars **don't exist** for that package |
| Data exfiltration | network **doesn't work** — ECONNREFUSED |
| Staged exfiltration | content hash **tracked** across all transforms |
| Filesystem snooping | files **don't exist** — ENOENT |
| Cryptomining | shell **doesn't work** — spawn ENOENT |
| Supply chain pivot | DNS **returns nothing** — ENOTFOUND |
| Maintainer takeover | behavioral DNA **catches any mutation** |
| Time-bomb | static scanner **detects** date/condition patterns |
| Zero-day | behavior changed = flagged. **no signature needed.** |
| Typosquatting | registry watcher + decoy traps |
| Native addon bypass | kernel policies **enforce at OS level** |
| AI-generated malware | physics > patterns. **can't steal what doesn't exist.** |
| Future unknown attacks | precognition models **predict what's coming** |

---

## 🤔 "How is this free?"

```
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│   What others charge:                                              │
│                                                                    │
│     CVE scanning .......................... $25K - $100K / year     │
│     License compliance .................... $30K / year             │
│     Dependency analysis ................... $30K - $150K / year     │
│     Runtime protection .................... $100K+ / year           │
│     Registry proxy ........................ $50K - $200K / year     │
│     SBOM + compliance ..................... $50K+ / year            │
│     Reachability analysis ................. $50K+ / year            │
│                                                                    │
│   Total: $200K - $500K / year                                      │
│                                                                    │
│   ─────────────────────────────────────────────────────────────    │
│                                                                    │
│   Sudarshana:  $0                                                  │
│                0 dependencies                                      │
│                660 KB                                               │
│                Works offline                                        │
│                Forever                                              │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## 🧬 Philosophy

Named after the **Sudarshana Chakra** — the divine disc that doesn't warn, doesn't negotiate, doesn't wait. It severs.

Most security tools are **observers**. They watch the theft happen and write a report.

Sudarshana makes theft *physically impossible*. A package can't exfiltrate credentials it cannot see. Can't phone home to a domain that doesn't resolve. Can't read a file that doesn't exist in its universe.

When something mutates — the disc doesn't need a signature. Behavior changed. That's enough.

When something will be attacked — the disc sees it coming. Attacker economics don't lie.

> The disc exists beyond time, beyond language, beyond identity.
> It is the immune system of all software that will ever be written.

---

## 📋 Requirements

- Node.js >= 16
- Works on Linux, macOS, Windows
- Zero external dependencies
- Works offline (except `vuln` command which queries OSV.dev)

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We especially need help with:

- More package presets
- Edge case discovery
- Evasion research

---

<br>

<p align="center">

```
Conceived and forged by lw0x × bb1nfosec

"The disc doesn't warn. It severs."

Free. Because the vault doesn't ask if you can afford it.
It just protects what's inside.
```

</p>

<br>

<p align="center">
  <strong>MIT License</strong>
  <br>
  <br>
  <code>0x00 — every package thinks it's alone. it is.</code>
</p>
