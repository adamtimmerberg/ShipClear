---
description: Run the full ShipClear gate — deterministic scan plus semantic security review — and deliver a plain-English safe-to-ship verdict.
---

<!-- GENERATED from core/gate-checklist.md by scripts/build-adapters.mjs. Do not edit by hand — edit the core file and run `npm run build:adapters`. -->

# Safe to ship?

The user wants to know whether this project is safe to deploy or share publicly. Run the complete ShipClear gate.

## How to run the gate

1. Run the deterministic scan: `npx --yes shipclear ship` (it writes `SHIP-REPORT.md` and applies safe fixes automatically).
2. Read `SHIP-REPORT.md` and walk the user through each finding in plain English.
   - **Never run `shipclear ship --fix-history` on the user's behalf.** It erases git history. If a finding recommends it, explain what it does, confirm the other findings are fixed first, and let the user run it — or run it only after they explicitly say to.
3. Perform the semantic checks below yourself — these need code understanding and are your responsibility:

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

Finish by telling the user the final verdict in one clear sentence, and exactly what stands between them and ✅ if they are not there yet.
