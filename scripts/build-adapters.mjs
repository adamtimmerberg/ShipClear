// Generates every tool-specific adapter from the canonical core files, so the
// rules can never drift between AI tools. Run `npm run build:adapters` after
// editing core/, or `npm run check:adapters` (CI does) to verify no drift.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
// Normalize on read: a CRLF-checked-out core file (Windows without
// .gitattributes honored) would otherwise leave stray \r at the end of
// every line after the .split('\n') calls below, and bake CRLF into every
// generated adapter.
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8').replace(/\r\n/g, '\n');

const prevention = read('core/prevention.md');
const checklist = read('core/gate-checklist.md');

// Body of the prevention rules, without the H1 (each adapter frames it).
const preventionBody = prevention.split('\n').slice(1).join('\n').trim();

const semantic = checklist
  .split('## Semantic layer (performed by the host AI via adapters)')[1]
  .split('## Verdict rules')[0]
  .trim();
const verdictRules = checklist.split('## Verdict rules')[1].trim();

const banner = (src) =>
  `<!-- GENERATED from ${src} by scripts/build-adapters.mjs. Do not edit by hand — edit the core file and run \`npm run build:adapters\`. -->`;

const shipSteps = `## How to run the gate

1. Run the deterministic scan: \`npx --yes shipclear ship\` (it writes \`SHIP-REPORT.md\` and applies safe fixes automatically).
2. Read \`SHIP-REPORT.md\` and walk the user through each finding in plain English.
3. Perform the semantic checks below yourself — these need code understanding and are your responsibility:

${semantic}

## Verdict rules

${verdictRules}

Finish by telling the user the final verdict in one clear sentence, and exactly what stands between them and ✅ if they are not there yet.`;

const OUTPUTS = {
  'adapters/claude-code/skills/shipclear-prevention/SKILL.md': `---
name: shipclear-prevention
description: Secure-by-default rules for AI-assisted coding. Use for EVERY coding task in every project — creating files, writing features, testing, seeding data. Covers secrets handling, .env/.gitignore setup, no hardcoded accounts, no real data in repos, and secure stack defaults.
---

${banner('core/prevention.md')}

# ShipClear prevention rules

${preventionBody}
`,

  'adapters/claude-code/commands/safe-to-ship.md': `---
description: Run the full ShipClear gate — deterministic scan plus semantic security review — and deliver a plain-English safe-to-ship verdict.
---

${banner('core/gate-checklist.md')}

# Safe to ship?

The user wants to know whether this project is safe to deploy or share publicly. Run the complete ShipClear gate.

${shipSteps}
`,

  'adapters/codex/AGENTS.md': `${banner('core/prevention.md')}
<!-- Append this file's contents to your project's AGENTS.md (or drop it in as-is). -->

# ShipClear security rules

${preventionBody}

## Before shipping

When the user wants to deploy or make the repository public, run \`npx --yes shipclear ship\`, then perform the semantic checks in \`SHIP-REPORT.md\` and restate the verdict.
`,

  'adapters/cursor/shipclear.mdc': `---
description: ShipClear secure-by-default rules for AI-assisted coding — apply to every task
alwaysApply: true
---

${banner('core/prevention.md')}

# ShipClear prevention rules

${preventionBody}
`,

  'adapters/gemini/GEMINI.md': `${banner('core/prevention.md')}
<!-- Append this file's contents to your project's GEMINI.md (or drop it in as-is). -->

# ShipClear security rules

${preventionBody}

## Before shipping

When the user wants to deploy or make the repository public, run \`npx --yes shipclear ship\`, then perform the semantic checks in \`SHIP-REPORT.md\` and restate the verdict.
`,

  'adapters/generic/INSTRUCTIONS.md': `${banner('core/prevention.md + core/gate-checklist.md')}
<!-- For any AI tool or local model: paste this file into your system prompt or project context. -->

# ShipClear security instructions

${preventionBody}

# The safe-to-ship gate

${shipSteps}
`,
};

const check = process.argv.includes('--check');
let drift = false;

// .gitattributes pins checkouts to LF, but this stays as defense-in-depth
// against any environment where that isn't honored (a stale clone, an
// editor that re-saves with CRLF) — normalize before comparing so line
// endings alone are never mistaken for real drift.
const normalizeEol = (s) => s.replace(/\r\n/g, '\n');

for (const [rel, content] of Object.entries(OUTPUTS)) {
  const abs = path.join(root, rel);
  if (check) {
    const existing = fs.existsSync(abs) ? fs.readFileSync(abs, 'utf8') : null;
    const matches = existing !== null && normalizeEol(existing) === normalizeEol(content);
    if (!matches) {
      console.error(`DRIFT: ${rel} does not match the canonical core. Run \`npm run build:adapters\`.`);
      drift = true;
    }
  } else {
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
    console.log(`generated ${rel}`);
  }
}

if (check) {
  if (drift) process.exit(1);
  console.log('adapters match the canonical core ✔');
}
