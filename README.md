<div align="center">

# 🛡️ ShipClear

**The last command before you launch.**

Your AI writes code fast. ShipClear makes sure it's safe to ship —
free, open source, runs 100% locally, works with every AI coding tool.

[![ShipClear](https://github.com/adamtimmerberg/ShipClear/actions/workflows/shipclear.yml/badge.svg?branch=main&event=push)](https://github.com/adamtimmerberg/ShipClear/actions/workflows/shipclear.yml)
[![CI](https://github.com/adamtimmerberg/ShipClear/actions/workflows/ci.yml/badge.svg)](https://github.com/adamtimmerberg/ShipClear/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](package.json)

</div>

---

You built something with AI — Claude Code, Cursor, Codex, Bolt, Lovable, a local model. It works! But before you deploy it or make the repo public, one question matters:

> **Is there anything in here that will hurt me the moment it's public?**

A scan of 5,600 AI-built apps found 2,000+ vulnerabilities and 400 exposed API keys. Leaked keys turn into real bills; the `admin@test.com / password123` account your AI made "for testing" turns into a real breach. ShipClear exists so that never happens to you.

## One command

*(Never typed a command before? [Start here](docs/quickstart.md#first-time-typing-a-command-start-here) — it takes two minutes.)*

```bash
npx shipclear ship
```

That runs the full gate and gives you a verdict:

```
  +--------------------------------------------------+
  |  ████ █  █ ████ ████   ████ █    ████  ██  ███   |
  |  █    █  █  ██  █  █   █    █    █    █  █ █  █  |
  |  ████ ████  ██  ████   █    █    ███  ████ ███   |
  |     █ █  █  ██  █      █    █    █    █  █ █ █   |
  |  ████ █  █ ████ █      ████ ████ ████ █  █ █  █  |
  |                                                  |
  |  v1.3.0 — ship report                            |
  +--------------------------------------------------+
  MIT · runs on your machine · nothing is uploaded

  Running 25 checks:
  [✓] Secrets written in your code
  [✗] Logins hardcoded in your code — 1 to look at
  [✓] Secrets anywhere in your git history
  [–] Known-vulnerable dependencies
  …

  🛑 CRITICAL  A secret key is written directly in your code
      where: server.js:1 — OpenAI API key: `sk-FAKE0…`
      why it matters: Anyone who sees this code — on GitHub, in a screenshot, in
      your deployed app — can use this key as you, and you get the bill.
      what to do: Move the value into your .env file and read it from an
      environment variable. Then rotate the key: log in to the provider and
      generate a new one, because this one is burned.

  Fixed for you:
   ✔ Added `.env` protection to .gitignore (created it if missing).

  23 of 25 checks ran · 2 skipped
  🛑 DO NOT SHIP — fix the critical findings first.

  Not checked here:
   – Known-vulnerable dependencies: no package-lock.json, so your dependencies
     were not checked for known vulnerabilities.
     To check them:
       Create the file npm reads, which also installs your packages:
       `npm install`
       Then run `npx shipclear ship` again — the check runs on its own.

  ────────────────────────────────────────────────────────────
  WHAT TO DO NEXT
  ────────────────────────────────────────────────────────────
   1. Rotate the keys listed above — now, before anything else. That is the step
      that actually protects you; the rest is cleanup.
   2. Fix the findings. If you built this with an AI, paste it this:
        "Read SHIP-REPORT.md in this project and fix every finding, the critical
         ones first. Don't rewrite git history, and don't run any shipclear command
         with --fix-history or --probe — tell me if a finding needs one and I'll
         run it myself."
   3. Run `npx shipclear ship` again, and keep going until the verdict changes.

  Disclaimer: ShipClear runs a limited set of automated checks. It is a
  supplement to security review, not a substitute for one, and a clear
  verdict is not a guarantee that your software is secure.
```

Every finding answers three questions in plain English: **what is this, why does it matter, what do I do.** Safe fixes are applied for you. No security background needed.

Note the `[–]` line. ShipClear tells you which checks it could **not** run here and what to type to turn them on — because "all checks passed" on a project whose dependencies were never looked at is the false all-clear this tool exists to prevent.

## Commands

Everything is one word plus, occasionally, one flag. `shipclear --help` prints this same list in your terminal.

| Command | What it does |
|---|---|
| `npx shipclear setup` | Prepares the project once: creates `.env` and a safe-to-share `.env.example`, adds `.env` to `.gitignore`, installs a commit guard that blocks secrets from ever being committed. |
| `npx shipclear scan` | Quick look for secrets in your current files. Fast, partial — it skips git history and dependencies, and says so. |
| `npx shipclear scan --staged` | Scans only what you're about to commit. This is what the commit guard runs; you rarely type it. |
| `npx shipclear ship` | **The one that matters.** The full gate: every check below, safe fixes applied for you, `SHIP-REPORT.md` written, and one verdict — cleared to ship, or not. |
| `npx shipclear ship --no-fix` | Same, but changes nothing — judges the project exactly as it stands. |
| `npx shipclear ship --strict` | Same, but any finding at all fails (exit 1). For CI and the badge, where "ship with fixes" can't count as a pass. |
| `npx shipclear ship --probe https://your-app.com` | Also asks your deployed site what is actually reachable. Read-only, confirms with you first — see [below](#checking-the-site-you-actually-deployed). |
| `npx shipclear ship --fix-history` | Erases git history to remove a leaked secret from old commits. Only for repos never pushed anywhere, refuses if it would lose any work, and never run for you by an AI assistant. |
| `npx shipclear badge` | Adds the self-updating ["cleared to ship" badge](#the-badge-cant-lie) to your README. |
| `npx shipclear --version` | Prints the version you're running. |

Stuck on something a report told you? [Plain-English troubleshooting and glossary](docs/troubleshooting.md).

## Three layers, not just a scanner

Most tools scan your app *after* you've made the mistake. ShipClear rides along the whole time:

| Layer | What it does |
|---|---|
| 🧠 **Prevention** | Rules for your AI assistant so secrets never get hardcoded in the first place — `.env` from the first line of code, no test accounts, no real data in the repo. |
| 🚫 **Enforcement** | A git commit guard (`shipclear setup`) that blocks any commit containing secrets or a `.env` file. Deterministic — it isn't the AI deciding to be careful. (If the scanner itself can't run — you're offline, say — it lets the commit through with a warning rather than blocking your work; it fails safe, not stuck.) |
| ✅ **The gate** | `shipclear ship`: 25 deterministic checks — across your code, your git history, *and* the config you deploy with (`.env`, docker-compose, proxy routes, bucket policies) — plus a semantic checklist for your AI, ending in one verdict — cleared to ship, or not. It prints every check as it runs, and says plainly which ones it could **not** run here and why, because "all checks passed" on a project whose dependencies were never looked at is the false all-clear this tool exists to prevent. Found a secret in old commits? `shipclear ship --fix-history` erases that history safely (never-pushed repos only; it refuses if it would lose anything). |

## Works with every AI coding tool

One canonical rule set, generated into every format ([how](scripts/build-adapters.mjs)):

| Tool | Setup |
|---|---|
| **Claude Code** | `/plugin marketplace add adamtimmerberg/ShipClear` then install `shipclear` — you get the prevention skill, a hook that blocks secret-bearing commits, and the `/safe-to-ship` command |
| **Codex CLI** | Append [`adapters/codex/AGENTS.md`](adapters/codex/AGENTS.md) to your project's `AGENTS.md` |
| **Cursor** | Copy [`adapters/cursor/shipclear.mdc`](adapters/cursor/shipclear.mdc) into `.cursor/rules/` |
| **Gemini CLI** | Append [`adapters/gemini/GEMINI.md`](adapters/gemini/GEMINI.md) to your `GEMINI.md` |
| **Any local model / other tool** | Paste [`adapters/generic/INSTRUCTIONS.md`](adapters/generic/INSTRUCTIONS.md) into your system prompt |
| **No AI at all** | The CLI works standalone: `npx shipclear setup && npx shipclear ship` |

Full walkthroughs: [docs/quickstart.md](docs/quickstart.md). Stuck on anything? [docs/troubleshooting.md](docs/troubleshooting.md) answers the questions first-timers actually hit, in plain English.

## What the gate checks

**In your code and git history:** secrets in your code **and in every past commit** (deleting a key doesn't un-leak it) · and in the files you haven't committed yet — the gate judges what your next `git add -A` would include, not only what git already has, because "build it, check it, then commit and push" is the order people actually work in · committed `.env` and private key files · real-looking values in `.env.example` · `.gitignore` coverage · personal data (emails, SSNs) in tracked data files · hardcoded login accounts · known-vulnerable dependencies · debug mode left on · certificate checking switched off · your local paths and AI-session artifacts leaking into the repo.

**In the config you deploy with** — the part that is still risky when the code is clean: a password that is still your `.env.example`'s value or the service's documented default (`minioadmin`, `postgres`, `change-me…`) · a missing variable that silently falls back to a known one (`${POSTGRES_PASSWORD:-dev-password}`) · storage anyone can read **or list** · a public route that forwards straight into your database, queue or object store · `/metrics`, `/actuator/env` and friends with no login · security headers set on your API but not on the pages a browser loads · a server that will fetch any web address a user hands it.

Provider keys covered: AWS, Anthropic, OpenAI, OpenRouter, Groq, xAI, Hugging Face, Stripe, GitHub, Google, Slack, SendGrid, npm, DigitalOcean, Azure, private keys, database URLs with real passwords — and Supabase JWTs done right: service-role keys are flagged, anon keys (public by design) are left alone.

The dependency check reads npm's `package-lock.json`. If your project uses pnpm, yarn, bun, or isn't JavaScript at all, ShipClear says so rather than reporting a pass it didn't earn, and tells you how to check — your package manager's own audit, or `osv-scanner`, which it then uses automatically for every ecosystem.

Detection is tuned against real-world starter repos, with a false-positive regression test for every fix. And if you have `gitleaks` or `osv-scanner` installed, ShipClear automatically uses them for extra depth — it just never *requires* them.

Plus a 15-point semantic checklist your AI assistant runs — the checks a regex can't do: auth **and ownership** on every route, database rules, client-side leakage, injection/XSS/uploads, server-side trust (prices, roles, webhook signatures), session hygiene and rate limiting, debug surface, an AI-surface review for apps that call LLMs themselves (prompt injection, unvalidated model output, overprivileged tools), and — confirmed by asking, not by reading config — whether your live credentials differ from the published ones, whether anything can list your buckets, whether a proxy route exposes a backing service, whether user-supplied URLs are fetched safely, and whether your HTML responses carry the headers your API does.

## The badge can't lie

Pass the gate and `shipclear badge` adds a **cleared to ship** badge to your README — one command, and it maintains itself from then on:

```bash
npx shipclear badge
```

Most badges are a static green image: paste it once and it keeps vouching for every commit you make afterwards, checked or not. That's a security claim nobody verified, which is exactly what this tool exists to prevent — so ShipClear doesn't hand you one. Instead `shipclear badge` installs a GitHub Actions workflow that re-runs this gate on GitHub for **every push**, and a badge that shows that workflow's real result:

| | means |
|---|---|
| 🟢 **passing** | every commit pushed to this branch cleared these automated checks (the semantic checklist needs a person or an AI, and no CI job runs it) — including its git history, so an old leaked secret keeps it red until the history is actually cleaned |
| 🔴 **failing** | a commit landed that ShipClear would not clear |
| ⚪ **no status** | nothing has been checked, so nothing is claimed |

The workflow runs `shipclear ship --no-fix --strict`: `--no-fix` so the verdict describes the commit as pushed rather than a copy the job quietly repaired, and `--strict` so only a full CLEARED counts as green. Skipping the gate locally can't produce a green badge — only a real passing run on GitHub can. (`--strict` is useful in your own CI for the same reason.)

Deleting the workflow or turning off Actions doesn't fake a green badge either — the badge drops to "no status". Nothing stops someone from deliberately pointing the badge at a different workflow; it defends against forgetting, not fraud.

## Checking the site you actually deployed

Some problems don't exist in your files. A storage bucket's permissions are applied at runtime; a missing response header is an absence; a proxy route's real behaviour is a behaviour. So the gate can also ask your live site:

```bash
npx shipclear ship --probe https://your-app.com
```

It reports what is genuinely reachable — an open `/metrics` or `/api/docs`, a storage folder that hands out a list of every file in it, a home page served without the headers that protect pages — and confirms (or quietly drops) the findings the file scan could only suspect.

The rules it works under: **`GET` only**, so nothing is written, changed or deleted; no logins, passwords, or attempts to get past anything; only the one address you type and paths beneath it; and it tells you all of that and waits for a yes before the first request. It's off unless you ask for it, and the AI adapters are instructed never to run it on your behalf. Only point it at a site you own.

## Privacy, by architecture

ShipClear runs entirely on your machine. **No account. No server. No telemetry. Nothing is uploaded, ever.** It has zero runtime dependencies — what you install is what's in this repo, and CI enforces that by not having an install step.

The single exception is opt-in and explicit: `ship --probe <url>` makes read-only requests to the address you give it, after asking. It still sends nothing anywhere else, and no part of your code or report leaves your machine.

## What ShipClear can't do

Honesty is a feature in a security tool. ShipClear is a **supplement to security review, not a substitute for one** — a clear verdict is not a guarantee that your software is secure, and the tool says so on every run. Specifically, it does **not**: audit your business logic, protect against DDoS, review your cloud console settings, or replace a professional security audit for high-stakes products. It doesn't pen-test your deployment either — `--probe` makes a handful of read-only requests to pages that shouldn't be public, which is a long way from a penetration test. It also can't catch a secret format nobody has taught it — if you find one it misses, [that's a security bug and we treat it like one](SECURITY.md).

## Updates

Build-in-public notes, new checks, and the occasional horror story about what ShipClear caught: **[@ShipClearCode](https://x.com/ShipClearCode)** on X. Watching [releases](https://github.com/adamtimmerberg/ShipClear/releases) works just as well if you'd rather not have an account.

## Contributing

Detection gaps, better plain-English explanations, and new adapters are all welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). ShipClear runs its own gate in CI on every commit; it will never ask you to ship what it wouldn't.

## License

[MIT](LICENSE) © Adam Timmerberg
