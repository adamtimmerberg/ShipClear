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
2. **Auth and ownership:** enumerate every route/endpoint; confirm each one either requires authentication or is intentionally public (list the public ones). For every authenticated resource access, confirm the code checks the resource *belongs to the requester* — an ID in a URL or request body must never be enough on its own.
3. **Database exposure:** review Firebase rules / Supabase RLS / equivalent for world-readable or world-writable access. Deny-by-default expected.
4. **Client-side leakage:** confirm no server secret is imported, bundled, or rendered into anything delivered to the browser.
5. **Input handling:** user input reaching SQL/NoSQL/shell must be parameterized; user content rendered into HTML must be escaped or sanitized; file uploads must validate type and enforce a size limit.
6. **Server-side trust:** anything with consequences must be computed or verified server-side — prices and entitlements (never trust totals from the client), roles and privileged fields (no mass-assignment of `role`/`isAdmin` from request bodies), and incoming webhooks (verify the signature before processing).
7. **Session and abuse surface:** session tokens in httpOnly cookies rather than localStorage; rate limiting (or provider-equivalent) on login, signup, and password-reset endpoints.
8. **Debug surface:** look for debug endpoints, verbose stack traces returned to users, `console.log` of sensitive values, and permissive CORS on authenticated APIs.
9. **AI surface** (when the app itself calls LLMs or runs agents/MCP tools): treat user input and any external content entering prompts as untrusted; never execute, render as HTML, or write to the database unvalidated model output; give agent/MCP tools the narrowest permissions that work, and keep agents away from production resources during testing.
10. **Report merge:** append semantic findings to `SHIP-REPORT.md` in the same *What / Why / Fix* format, then restate the final verdict — a semantic critical downgrades the overall verdict to DO NOT SHIP.

## Verdict rules

- Any **critical** finding → 🛑 **DO NOT SHIP**
- Any **high** or **medium** finding (no criticals) → 🟡 **SHIP WITH FIXES**
- Only low/info notes → ✅ **CLEARED TO SHIP**

A false ✅ is the worst possible outcome and always takes priority over false-positive comfort.
