# Quickstart

Every path below ends the same way: run `npx shipclear ship` before you deploy or make the repo public, and get a plain-English verdict.

## First time typing a command? Start here.

Every instruction below happens in a **terminal** — a text window where you type commands instead of clicking buttons. If you've only ever built with AI tools in the browser, here's where to find one:

- **Bolt.new / Lovable / Replit / v0:** look for a "Terminal" or "Console" tab or panel, usually near the bottom of the screen or behind a `>_` icon. Once you find it, skip straight to **["Use the standalone CLI"](#use-the-standalone-cli-works-with-any-ai-tool-or-none)** below — these tools' AI runs in your browser, not as a terminal agent ShipClear plugs into, so that's the section for you.
- **Cursor / VS Code:** the menu bar → **Terminal → New Terminal**.
- **Mac:** open the **Terminal** app (search for it with Spotlight, ⌘+Space).
- **Windows:** open **PowerShell** or **Windows Terminal** from the Start menu.

Once it's open, make sure you're inside your project's folder: type `cd ` (with a space), then the folder's path — e.g. `cd my-app` if it's right there, or on a Mac just drag the folder onto the terminal window to paste its path. Then type the commands below and press Enter.

**If an `npx` command says `command not found`:** you'll also need [Node.js](https://nodejs.org) installed — it's what runs `npx`. Download the "LTS" version, install it like any other app, then try again. (If a *different* command says this — one that doesn't start with `npx` — that specific tool isn't installed; Node.js won't fix it.)

## Which section below is yours?

- You talk to your AI **in a browser tab** (Bolt, Lovable, Replit, v0, ChatGPT, Claude.ai) → [Use the standalone CLI](#use-the-standalone-cli-works-with-any-ai-tool-or-none).
- You talk to your AI **inside your code editor or terminal** (Claude Code, Codex, Cursor, Gemini CLI) → find it by name below; you get the extra layers (prevention rules, commit guard).
- Not sure, or none of the above → the standalone CLI works for everyone.

## Claude Code (recommended: the full plugin)

```
/plugin marketplace add adamtimmerberg/ShipClear
/plugin install shipclear@shipclear
```

You now have all three layers:
- the **prevention skill** — Claude builds with secure defaults on every task;
- the **commit guard** — a hook blocks `git commit` / `git push` while staged changes contain secrets;
- the **`/safe-to-ship` command** — the full gate plus Claude's semantic review, ending in a verdict.

## Codex CLI

1. Copy the contents of [`adapters/codex/AGENTS.md`](../adapters/codex/AGENTS.md) into your project's `AGENTS.md` (create it if needed).
2. In your project: `npx shipclear setup` (installs the git commit guard).
3. Before launch, ask Codex to run the gate, or run `npx shipclear ship` yourself.

## Cursor

1. Copy [`adapters/cursor/shipclear.mdc`](../adapters/cursor/shipclear.mdc) to `.cursor/rules/shipclear.mdc` in your project.
2. `npx shipclear setup`
3. Before launch: `npx shipclear ship`, then ask Cursor to complete the semantic checklist in `SHIP-REPORT.md`.

## Gemini CLI

1. Append [`adapters/gemini/GEMINI.md`](../adapters/gemini/GEMINI.md) to your project's `GEMINI.md`.
2. `npx shipclear setup`
3. Before launch: `npx shipclear ship`.

## Any other tool, or a local model

1. Paste [`adapters/generic/INSTRUCTIONS.md`](../adapters/generic/INSTRUCTIONS.md) into your system prompt or project context.
2. `npx shipclear setup`
3. Before launch: `npx shipclear ship`.

## Use the standalone CLI (works with any AI tool, or none)

This is the path for **Bolt.new, Lovable, Replit, v0**, or anyone without a terminal-integrated AI coding tool — including if you're not using AI at all. ShipClear is a complete standalone CLI:

```bash
npx shipclear setup   # .env/.env.example/.gitignore + commit guard
npx shipclear scan    # quick secrets check any time
npx shipclear ship    # the full gate → SHIP-REPORT.md + verdict
npx shipclear ship --fix-history
                      # after fixing everything else: erase old commits that held a secret
                      # (only for repos never pushed anywhere; refuses if it would lose any work)
```

The full report (`SHIP-REPORT.md`) ends with a checklist meant for an AI to work through with you — if you don't have one built into your terminal, paste that checklist and your code into any AI chat (ChatGPT, Claude.ai, Gemini — even a free one) and ask it to go through the list, or ask a developer friend.

## Reading the verdict

- ✅ **CLEARED TO SHIP** — no blocking findings.
- 🟡 **SHIP WITH FIXES** — nothing catastrophic; close the listed items first.
- 🛑 **DO NOT SHIP** — a critical finding (a leaked secret, a committed `.env`) needs fixing *and* usually a key rotation. The report tells you exactly what to do, step by step.

## False positives

Real-world code sometimes trips a pattern. Add the file path to a `.shipclearignore` in your project root (one path or glob per line) — and please [tell us](https://github.com/adamtimmerberg/ShipClear/issues/new?template=false_positive.md) so the pattern gets fixed for everyone.
