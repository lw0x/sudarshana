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

Or as a require hook (works with any runner):

```bash
node --require sudarshana app.js
```

That's it. No code changes. No config files to maintain (unless you want to).

---

## How it works (30 seconds)

1. **Intercepts `require()`** — every module load goes through Sudarshana first
2. **Identifies the caller** — uses call-stack attribution to know which *package* is asking
3. **Applies per-package policy** — each package gets a virtual environment tailored to its needs
4. **Monitors behavior** — if a package reads credentials then makes a network call within 5 seconds, that's flagged as exfiltration
5. **Plants honeypots** — fake `AWS_SECRET_ACCESS_KEY` values that look real but trigger alerts if accessed

All of this happens in ~2ms overhead per require call. Your app runs at normal speed.

---

## The attacks it stops

| Attack | Real-world example | How Sudarshana stops it |
|--------|-------------------|------------------------|
| Credential theft | `event-stream` (2018) | Package can't see real env vars — only honeypots |
| Data exfiltration | `@azure/identity` theft (2023) | Network blocked to undeclared domains |
| Filesystem snooping | `node-ipc` protest-ware (2022) | Can't write outside its own directory |
| Cryptomining | `ua-parser-js` hijack (2021) | Shell execution blocked |
| Supply chain pivot | Ledger Connect Kit (2023) | DNS resolution fails for attacker domains |

---

## Zero config

Run `sudarshana init` and it figures out your dependency graph. It knows that:
- `lodash`, `ramda`, `underscore` → pure compute, need nothing
- `express`, `fastify`, `koa` → need PORT and localhost binding
- `pg`, `mysql2`, `prisma` → need DATABASE_URL and db host
- `aws-sdk`, `@aws-sdk/*` → need AWS_* vars and *.amazonaws.com

You can override anything in `sudarshana.config.json` if needed. But most projects work out of the box.

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
