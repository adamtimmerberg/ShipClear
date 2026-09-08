# Security Policy

ShipClear is a security tool, so we hold ourselves to the standard we ask of others.

## Reporting a vulnerability

If you find a vulnerability in ShipClear itself — a bypass of the commit guard, a pattern-evasion technique, a case where the gate says SAFE when it shouldn't — please report it privately:

1. **Preferred:** use GitHub's private vulnerability reporting — the **Security** tab of this repository → *Report a vulnerability*.
2. If that isn't possible, email **adamtimmerberg@gmail.com** with `[ShipClear Security]` in the subject.

Please include reproduction steps and, if you can, a minimal fixture file that demonstrates the issue.

## What to expect

- Acknowledgement within **72 hours**.
- A fix or a documented mitigation for confirmed issues as quickly as severity warrants — detection bypasses are treated as the highest severity.
- Credit in the release notes (if you want it) once the fix ships.

## Scope notes

- **False negatives are vulnerabilities.** If ShipClear misses a secret format it claims to detect, that's a security bug — report it privately.
- **False positives are ordinary bugs.** Please open a public issue with the `false positive` template instead.
- ShipClear runs entirely locally and makes no network calls of its own (the optional `npm audit` integration talks to the npm registry). Anything that violates that promise is a critical bug.
