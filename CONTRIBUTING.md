# Contributing to ShipClear

Thanks for helping make AI-built apps safer to ship. Contributions of every size are welcome — new detection patterns, better plain-English explanations, adapter improvements, docs, and bug reports all count.

## Ground rules

- **Zero runtime dependencies.** The CLI must keep working on a bare `npx shipclear` with nothing else installed. External scanners (gitleaks, npm audit) are optional enhancements, never requirements.
- **Deterministic first.** Anything that can be caught by a pattern must be caught by a pattern. The LLM layer (adapters) is only for checks that genuinely require semantic understanding.
- **Plain English everywhere.** Every finding must answer three questions for someone with no security background: *What is this? Why does it matter? What do I do?* If your explanation needs jargon, rewrite it.
- **No false GO verdicts.** A missed finding that lets someone ship a leaked key is the worst failure mode. When tuning patterns, prefer a small number of clearly-labeled warnings over silence.

## Getting started

```bash
git clone https://github.com/adamtimmerberg/ShipClear.git
cd ShipClear
npm test              # runs the fixture-based test suite
npm run gate          # ShipClear must pass its own gate
npm run check:adapters  # adapters must match the canonical core
```

## Making changes

1. **Detection patterns** live in `cli/lib/patterns.js`. Add a fixture that proves your pattern catches the real thing (and doesn't catch placeholders) in `tests/fixtures/`.
2. **Prevention rules** live in `core/prevention.md` — the single source of truth. Never edit files under `adapters/` by hand; run `npm run build:adapters` to regenerate them.
3. **Gate checks** live in `cli/lib/checks.js`, with their plain-English explanations in `cli/lib/report.js`.
4. Run `npm test` and `npm run gate` before opening a PR.

## Commit style

We use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `chore:`, with an optional scope like `feat(cli):`. Keep commits focused — one logical change per commit.

## Reporting security issues in ShipClear itself

Please do not open a public issue — see [SECURITY.md](SECURITY.md).
