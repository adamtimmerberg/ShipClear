---
description: Run the full ShipClear gate — deterministic scan plus semantic security review — and deliver a plain-English safe-to-ship verdict.
---

<!-- GENERATED from core/gate-checklist.md by scripts/build-adapters.mjs. Do not edit by hand — edit the core file and run `npm run build:adapters`. -->

# Safe to ship?

The user wants to know whether this project is safe to deploy or share publicly. Run the complete ShipClear gate.

## How to run the gate

1. Run the deterministic scan: `npx --yes shipclear ship` (it writes `SHIP-REPORT.md` and applies safe fixes automatically).
2. Read `SHIP-REPORT.md` and walk the user through each finding in plain English.
3. Perform the semantic checks below yourself — these need code understanding and are your responsibility:

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

Finish by telling the user the final verdict in one clear sentence, and exactly what stands between them and ✅ if they are not there yet.
