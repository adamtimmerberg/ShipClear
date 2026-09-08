# Quickstart

Every path below ends the same way: run `npx shipclear ship` before you deploy or make the repo public, and get a plain-English verdict.

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

## No AI at all

ShipClear is a complete standalone CLI:

```bash
npx shipclear setup   # .env/.env.example/.gitignore + commit guard
npx shipclear scan    # quick secrets check any time
npx shipclear ship    # the full gate → SHIP-REPORT.md + verdict
```

## Reading the verdict

- ✅ **CLEARED TO SHIP** — no blocking findings.
- 🟡 **SHIP WITH FIXES** — nothing catastrophic; close the listed items first.
- 🛑 **DO NOT SHIP** — a critical finding (a leaked secret, a committed `.env`) needs fixing *and* usually a key rotation. The report tells you exactly what to do, step by step.

## False positives

Real-world code sometimes trips a pattern. Add the file path to a `.shipclearignore` in your project root (one path or glob per line) — and please [tell us](https://github.com/adamtimmerberg/ShipClear/issues/new?template=false_positive.md) so the pattern gets fixed for everyone.
