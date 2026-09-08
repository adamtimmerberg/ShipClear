# The ShipClear gate — canonical checklist

This is the full specification of what `shipclear ship` verifies (deterministic layer) and what the AI adapter layer verifies on top (semantic layer). The CLI implements every deterministic check; adapters instruct the host agent through every semantic check. A project passes the gate only when both layers are clean.

## Deterministic layer (implemented in the CLI)

| ID | Check | Severity when found |
|---|---|---|
| `secret-in-code` | Known secret formats (API keys, tokens, private keys, passwords in connection strings) in tracked files | critical |
| `secret-in-history` | Secrets present in any past commit, even if deleted since | critical |
| `env-tracked` | `.env` or other secrets files tracked by git | critical |
| `key-file-tracked` | Private key material (`.pem`, `id_rsa`, etc.) tracked by git | critical |
| `env-example-leak` | Real-looking values in `.env.example` | high |
| `gitignore-incomplete` | `.gitignore` missing `.env` coverage (or missing entirely) | high |
| `pii-data-file` | Tracked data files (CSV/TSV/SQL/JSONL) containing real-looking emails or SSNs | high |
| `test-account` | Hardcoded credential pairs (email + password literals) in source | high |
| `dependency-vulns` | Known CVEs in dependencies (`npm audit`, high and critical) | high |
| `generic-secret` | Suspicious hardcoded values assigned to names like `apiKey`, `password`, `token` | medium |
| `personal-path` | Absolute paths exposing local usernames (`/home/adam/...`, `C:\Users\...`) | low |
| `agent-artifact` | AI-session artifacts (local agent settings, transcripts) tracked by git | low |
| `env-example-missing` | `.env` exists but `.env.example` doesn't | info |

## Semantic layer (performed by the host AI via adapters)

1. **Hidden accounts:** search for any route, seed, migration, or conditional that grants access via a fixed credential, magic string, or special email — including ones the AI itself created during this project. Check `.shipclear/test-accounts.json` and confirm every listed credential is absent from code and the production database plan.
2. **Auth coverage:** enumerate every route/endpoint; confirm each one either requires authentication or is intentionally public. List the intentionally-public ones in the report.
3. **Database exposure:** review Firebase rules / Supabase RLS / equivalent for world-readable or world-writable access. Deny-by-default expected.
4. **Client-side leakage:** confirm no server secret is imported, bundled, or rendered into anything delivered to the browser.
5. **Debug surface:** look for debug endpoints, verbose stack traces returned to users, `console.log` of sensitive values, and permissive CORS on authenticated APIs.
6. **Report merge:** append semantic findings to `SHIP-REPORT.md` in the same *What / Why / Fix* format, then restate the final verdict — a semantic critical downgrades the overall verdict to DO NOT SHIP.

## Verdict rules

- Any **critical** finding → 🛑 **DO NOT SHIP**
- Any **high** or **medium** finding (no criticals) → 🟡 **SHIP WITH FIXES**
- Only low/info notes → ✅ **CLEARED TO SHIP**

A false ✅ is the worst possible outcome and always takes priority over false-positive comfort.
