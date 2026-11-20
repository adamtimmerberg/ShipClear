# The ShipClear gate — canonical checklist

This is the full specification of what `shipclear ship` verifies (deterministic layer) and what the AI adapter layer verifies on top (semantic layer). The CLI implements every deterministic check; adapters instruct the host agent through every semantic check. A project passes the gate only when both layers are clean.

## Deterministic layer (implemented in the CLI)

| ID | Check | Severity when found |
|---|---|---|
| `secret-in-code` | Known secret formats (API keys, tokens, private keys, passwords in connection strings) in tracked files | critical |
| `secret-in-history` | Secrets present in any past commit, even if deleted since | critical |
| `env-tracked` | `.env` or other secrets files tracked by git | critical |
| `key-file-tracked` | Private key material (`.pem`, `id_rsa`, etc.) tracked by git | critical |
| `key-file-uncommitted` | Private key material present in the project, not tracked and not git-ignored — the next `git add -A` would commit it | high |
| `env-example-leak` | Real-looking values in `.env.example` | high |
| `gitignore-incomplete` | `.gitignore` missing `.env` coverage (or missing entirely) | high |
| `pii-data-file` | Tracked data files (CSV/TSV/SQL/JSONL) containing real-looking emails or SSNs | high |
| `test-account` | Hardcoded credential pairs (email + password literals) in source | high |
| `dependency-vulns` | Known CVEs in dependencies (`npm audit`, high and critical) | high |
| `credential-in-use-is-public` | The live config (`.env`, compose, k8s, tfvars, Helm values) runs on a value copied from the project's own `.env.example`, a service's documented default, or a leftover placeholder | critical with a production signal, else medium |
| `public-bucket` | Object storage readable — or **listable** — by anyone (`mc anonymous set download`, `--acl public-read`, wildcard bucket policy, `allUsers`, Azure `container`, Firebase `if true`) | critical when listing or writing is granted, else medium |
| `proxy-exposes-service` | A public proxy/ingress route forwards wholesale into a backing service (database, queue, object store, admin UI) | critical for databases/queues/admin UIs, high for object storage |
| `debug-route-public` | A debug or monitoring path (`/metrics`, `/actuator/env`, `/debug/pprof`, `/api/docs`, `/adminer`…) served with no auth check and no production switch | critical when it exposes environment or memory, else medium |
| `ssrf-unchecked-fetch` | A URL arriving in a request is fetched by the server with no public-address check — or redirects are followed, which steps around one | high |
| `generic-secret` | Suspicious hardcoded values assigned to names like `apiKey`, `password`, `token` | medium |
| `secret-default-fallback` | A secret-ish variable has a working default, so a missing value silently becomes a known one (`${FOO_PASSWORD:-…}`, `os.getenv("X", "…")`, `process.env.X \|\| "…"`, settings-class defaults) | medium, critical when that default is the value actually in use |
| `headers-html-uncovered` | Security headers (CSP and friends) configured for the API only, or described in a proxy config's comments while it sets none — the HTML responses get nothing | medium |
| `tls-verification-off` | Certificate checking disabled (`rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False`) | medium |
| `debug-mode-on` | Framework debug mode left on in shipped code (`app.run(debug=True)`, `FLASK_DEBUG=1`) | medium |
| `personal-path` | Absolute paths exposing local usernames (`/home/adam/...`, `C:\Users\...`) | low |
| `agent-artifact` | AI-session artifacts (local agent settings, transcripts) tracked by git | low |
| `env-example-missing` | `.env` exists but `.env.example` doesn't | info |

**What the deterministic layer reads.** Content checks judge *what a commit would contain* — files git tracks, plus untracked files git is not ignoring (`git add -A`'s set). Checks that assert something *is committed* (`env-tracked`, `key-file-tracked`, `agent-artifact`) read git's tracked list only, so an untracked file is never described as committed. Deployment checks read the working tree, since the live `.env` is their subject and is correctly never tracked.

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
10. **Credentials actually in use:** every password, key and token in the live config differs from the value in the example/sample config and from the service's documented default. The app refuses to start in production if a placeholder remains.
11. **File and object storage:** no bucket or container is publicly readable; nothing anonymous can **list** its contents. Confirm with a request to the bucket root, not just by reading config.
12. **Proxy and ingress:** no public route forwards wholesale into a backing service (database, object store, queue, admin UI); routes are narrowed to the paths actually needed.
13. **Outbound fetches:** if the server fetches URLs supplied by users (import-from-URL, link previews, webhooks, avatars), internal and cloud-metadata addresses are refused — and re-checked after every redirect.
14. **Header coverage:** security headers apply to the responses that serve HTML, not only to the API.
15. **Report merge:** append semantic findings to `SHIP-REPORT.md` in the same *What / Why / Fix* format, then restate the final verdict — a semantic critical downgrades the overall verdict to DO NOT SHIP.

## Verdict rules

- Any **critical** finding → 🛑 **DO NOT SHIP**
- Any **high** or **medium** finding (no criticals) → 🟡 **SHIP WITH FIXES**
- Only low/info notes → ✅ **CLEARED TO SHIP**

A false ✅ is the worst possible outcome and always takes priority over false-positive comfort.
