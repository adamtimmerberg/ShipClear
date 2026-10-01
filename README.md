<div align="center">

# 🛡️ ShipClear

**The last command before you launch.**

Your AI writes code fast. ShipClear makes sure it's safe to ship —
free, open source, runs 100% locally, works with every AI coding tool.

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
  ShipClear v1.0.0 — ship report

  🛑 CRITICAL  A secret key is written directly in your code
      where: server.js:7 — OpenAI API key: `sk-FAKE0…`
      why it matters: Anyone who sees this code — on GitHub, in a screenshot, in
      your deployed app — can use this key as you, and you get the bill.
      what to do: Move the value into your .env file and read it from an
      environment variable. Then rotate the key: log in to the provider and
      generate a new one, because this one is burned.

  Fixed for you:
   ✔ Added `.env` protection to .gitignore (created it if missing).

  🛑 DO NOT SHIP — fix the critical findings first.
```

Every finding answers three questions in plain English: **what is this, why does it matter, what do I do.** Safe fixes are applied for you. No security background needed.

## Three layers, not just a scanner

Most tools scan your app *after* you've made the mistake. ShipClear rides along the whole time:

| Layer | What it does |
|---|---|
| 🧠 **Prevention** | Rules for your AI assistant so secrets never get hardcoded in the first place — `.env` from the first line of code, no test accounts, no real data in the repo. |
| 🚫 **Enforcement** | A git commit guard (`shipclear setup`) that blocks any commit containing secrets or a `.env` file. Deterministic — it isn't the AI deciding to be careful. (If the scanner itself can't run — you're offline, say — it lets the commit through with a warning rather than blocking your work; it fails safe, not stuck.) |
| ✅ **The gate** | `shipclear ship`: 13 deterministic checks + a semantic checklist for your AI, ending in one verdict — cleared to ship, or not. Found a secret in old commits? `shipclear ship --fix-history` erases that history safely (never-pushed repos only; it refuses if it would lose anything). |

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

Secrets in your code **and in your entire git history** (deleting a key doesn't un-leak it) · committed `.env` and private key files · real-looking values in `.env.example` · `.gitignore` coverage · personal data (emails, SSNs) in tracked data files · hardcoded login accounts · known-vulnerable dependencies · your local paths and AI-session artifacts leaking into the repo.

Provider keys covered: AWS, Anthropic, OpenAI, OpenRouter, Groq, xAI, Hugging Face, Stripe, GitHub, Google, Slack, SendGrid, npm, DigitalOcean, Azure, private keys, database URLs with real passwords — and Supabase JWTs done right: service-role keys are flagged, anon keys (public by design) are left alone.

Detection is tuned against real-world starter repos, with a false-positive regression test for every fix. And if you have `gitleaks` or `osv-scanner` installed, ShipClear automatically uses them for extra depth — it just never *requires* them.

Plus a ten-point semantic checklist your AI assistant runs — the checks a regex can't do: auth **and ownership** on every route, database rules, client-side leakage, injection/XSS/uploads, server-side trust (prices, roles, webhook signatures), session hygiene and rate limiting, debug surface, and an AI-surface review for apps that call LLMs themselves (prompt injection, unvalidated model output, overprivileged tools).

Pass the gate and you'll get a badge for your README: ![ShipClear: cleared to ship](https://img.shields.io/badge/ShipClear-cleared%20to%20ship-brightgreen)

## Privacy, by architecture

ShipClear runs entirely on your machine. **No account. No server. No telemetry. Nothing is uploaded, ever.** It has zero runtime dependencies — what you install is what's in this repo, and CI enforces that by not having an install step.

## What ShipClear can't do

Honesty is a feature in a security tool. ShipClear does **not**: audit your business logic, test your deployed infrastructure, protect against DDoS, review your cloud console settings, or replace a professional security audit for high-stakes products. It also can't catch a secret format nobody has taught it — if you find one it misses, [that's a security bug and we treat it like one](SECURITY.md).

## Contributing

Detection gaps, better plain-English explanations, and new adapters are all welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). ShipClear runs its own gate in CI on every commit; it will never ask you to ship what it wouldn't.

## License

[MIT](LICENSE) © Adam Timmerberg
