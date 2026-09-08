// Every finding gets three plain-English answers: what is this, why does it
// matter, what do I do. If an explanation needs jargon, it gets rewritten.
const EXPLAIN = {
  'secret-in-code': {
    title: 'A secret key is written directly in your code',
    why: 'Anyone who sees this code — on GitHub, in a screenshot, in your deployed app — can use this key as you, and you get the bill.',
    fix: 'Move the value into your .env file and read it from an environment variable. Then rotate the key: log in to the provider and generate a new one, because this one is burned.',
  },
  'secret-in-history': {
    title: 'A secret exists in your git history',
    why: 'Deleting a key from your code does not delete it from git — every past version stays downloadable. If this repo goes public, the old key goes public with it.',
    fix: 'Rotate the key now (generate a new one at the provider — this is the step that actually protects you). To also scrub history before going public, use `git filter-repo` or BFG Repo-Cleaner; ShipClear never rewrites history for you.',
  },
  'env-tracked': {
    title: 'Your .env file is checked into git',
    why: 'The .env file is your box of secrets. Committing it means every secret inside ships with the repo, forever, to everyone who can see it.',
    fix: 'Run `git rm --cached <file>` to untrack it (the file stays on your machine), commit, and rotate every key inside it. ShipClear has already made sure .gitignore prevents this happening again.',
  },
  'key-file-tracked': {
    title: 'A private key file is checked into git',
    why: 'Private key files (.pem, id_rsa and friends) are the literal keys to servers and services. Anyone with the repo can log in as you.',
    fix: 'Run `git rm --cached <file>`, add the filename to .gitignore, and generate a new key pair — the committed one can never be trusted again.',
  },
  'env-example-leak': {
    title: '.env.example contains a real-looking value',
    why: '.env.example is meant to be shared — it shows which settings exist, with the values blank. A real value here is a secret published on purpose.',
    fix: 'Replace the value with nothing (KEY=) or an obvious placeholder. If the value was real, rotate it.',
  },
  'gitignore-incomplete': {
    title: '.env files are not protected by .gitignore',
    why: 'Without this, one ordinary `git add .` commits your secrets. This is the single most common way keys leak.',
    fix: 'ShipClear fixed this for you — .gitignore now excludes .env files.',
  },
  'pii-data-file': {
    title: 'A data file with real-looking personal information is in the repo',
    why: 'Emails, SSNs, and customer records in a repo become public the moment the repo does. That is a privacy breach, and in many places a legal one.',
    fix: 'Untrack the file (`git rm --cached <file>`), add it to .gitignore, and use made-up data for testing and seeding instead.',
  },
  'test-account': {
    title: 'A login is hardcoded in the app',
    why: 'AI assistants often create accounts like admin@… "just for testing". If it ships, anyone who reads the code can log in to your live app with it.',
    fix: 'Delete the hardcoded credentials. If tests need an account, create it with random values at test time and keep them out of git.',
  },
  'dependency-vulns': {
    title: 'Dependencies have known security holes',
    why: 'These are published vulnerabilities with public write-ups — attackers scan for them automatically.',
    fix: 'Run `npm audit fix` and re-test the app. For anything it can\'t fix, `npm audit` names the package so you can update or replace it.',
  },
  'generic-secret': {
    title: 'A value that looks like a credential is hardcoded',
    why: 'Something named like a key, token, or password is assigned directly in the code. If it\'s real, it leaks with the repo.',
    fix: 'If it\'s a real credential: move it to .env and rotate it. If it\'s a harmless placeholder, make it look like one (empty, or "REPLACE_ME") so scanners stay calm — or add the file to .shipclearignore.',
  },
  'personal-path': {
    title: 'Your local file path (with your username) is in the code',
    why: 'Purely a privacy footprint: it reveals your computer\'s username and folder layout. Harmless to the app, but not something to publish.',
    fix: 'Use a relative path or an environment variable instead.',
  },
  'agent-artifact': {
    title: 'AI-tool working files are checked into git',
    why: 'Local agent settings and session files can contain machine details, and occasionally pasted secrets. They are your workspace, not your product.',
    fix: 'Untrack them (`git rm -r --cached <path>`) and add the folder to .gitignore.',
  },
  'env-example-missing': {
    title: 'No .env.example template exists',
    why: 'Not a leak — just a courtesy: a template tells collaborators (and AI agents) which settings exist without revealing any values.',
    fix: 'ShipClear created one from your .env, with all values stripped.',
  },
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_LABEL = {
  critical: '🛑 CRITICAL', high: '🔴 HIGH', medium: '🟠 MEDIUM', low: '🟡 LOW', info: 'ℹ️  INFO',
};

export function verdictOf(findings) {
  const open = findings.filter((f) => !f.resolved);
  if (open.some((f) => f.severity === 'critical')) return 'DO_NOT_SHIP';
  if (open.some((f) => f.severity === 'high' || f.severity === 'medium')) return 'SHIP_WITH_FIXES';
  return 'CLEARED';
}

export const VERDICT_TEXT = {
  DO_NOT_SHIP: '🛑 DO NOT SHIP — fix the critical findings first.',
  SHIP_WITH_FIXES: '🟡 SHIP WITH FIXES — nothing catastrophic, but close the items below first.',
  CLEARED: '✅ CLEARED TO SHIP — no blocking findings.',
};

function sorted(findings) {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
      || (a.file || '').localeCompare(b.file || '')
      || (a.line || 0) - (b.line || 0)
  );
}

function location(f) {
  if (!f.file) return '';
  return f.line ? `${f.file}:${f.line}` : f.file;
}

const color = (code, s) =>
  process.stdout.isTTY && !process.env.NO_COLOR ? `\x1b[${code}m${s}\x1b[0m` : s;

export function renderTerminal({ findings, notes, verdict, fixes = [], version }) {
  const lines = [];
  lines.push('');
  lines.push(color('1', `  ShipClear v${version} — ship report`));
  lines.push('');

  const open = sorted(findings.filter((f) => !f.resolved));
  for (const f of open) {
    const ex = EXPLAIN[f.id];
    lines.push(`  ${SEVERITY_LABEL[f.severity]}  ${color('1', ex.title)}`);
    if (location(f)) lines.push(`      where: ${location(f)}${f.detail ? ` — ${f.detail}` : ''}`);
    else if (f.detail) lines.push(`      ${f.detail}`);
    lines.push(`      why it matters: ${ex.why}`);
    lines.push(`      what to do: ${ex.fix}`);
    lines.push('');
  }
  if (open.length === 0) lines.push('  No findings. Nice.');
  if (fixes.length) {
    lines.push('');
    lines.push(color('1', '  Fixed for you:'));
    for (const fix of fixes) lines.push(`   ✔ ${fix}`);
  }
  for (const note of notes) lines.push(`  note: ${note}`);
  lines.push('');
  const v = VERDICT_TEXT[verdict];
  lines.push('  ' + color(verdict === 'CLEARED' ? '32;1' : verdict === 'DO_NOT_SHIP' ? '31;1' : '33;1', v));
  lines.push('');
  lines.push('  Full report written to SHIP-REPORT.md');
  lines.push('');
  return lines.join('\n');
}

export function renderMarkdown({ findings, notes, verdict, fixes = [], version, semanticSection = true }) {
  const open = sorted(findings.filter((f) => !f.resolved));
  const out = [];
  out.push('# Ship Report');
  out.push('');
  out.push(`> Generated by [ShipClear](https://github.com/adamtimmerberg/ShipClear) v${version} on ${new Date().toISOString().slice(0, 10)}`);
  out.push('');
  out.push(`## Verdict: ${VERDICT_TEXT[verdict]}`);
  out.push('');
  if (open.length === 0) {
    out.push('No findings from the deterministic scan.');
  } else {
    out.push(`## Findings (${open.length})`);
    for (const f of open) {
      const ex = EXPLAIN[f.id];
      out.push('');
      out.push(`### ${SEVERITY_LABEL[f.severity]} — ${ex.title}`);
      if (location(f)) out.push(`- **Where:** \`${location(f)}\`${f.detail ? ` — ${f.detail}` : ''}`);
      else if (f.detail) out.push(`- **Detail:** ${f.detail}`);
      out.push(`- **Why it matters:** ${ex.why}`);
      out.push(`- **What to do:** ${ex.fix}`);
    }
  }
  if (fixes.length) {
    out.push('');
    out.push('## Fixed automatically');
    for (const fix of fixes) out.push(`- ✔ ${fix}`);
  }
  if (notes.length) {
    out.push('');
    out.push('## Notes');
    for (const note of notes) out.push(`- ${note}`);
  }
  if (semanticSection) {
    out.push('');
    out.push('## Semantic checks — for your AI assistant');
    out.push('');
    out.push('The scan above catches everything a pattern can catch. These six need code understanding — ask your AI assistant to work through them (the ShipClear adapters do this automatically):');
    out.push('');
    out.push('- [ ] **Hidden accounts:** no route, seed, or conditional grants access via a fixed credential or magic string — including ones the AI created during development.');
    out.push('- [ ] **Auth coverage:** every endpoint either requires authentication or is intentionally public (list the public ones).');
    out.push('- [ ] **Database exposure:** no world-readable/world-writable rules (Firebase rules, Supabase RLS, etc.).');
    out.push('- [ ] **Client-side leakage:** no server secret reaches anything delivered to the browser.');
    out.push('- [ ] **Debug surface:** no debug endpoints, stack traces shown to users, or `*` CORS on authenticated APIs.');
    out.push('- [ ] **Verdict update:** append any semantic findings here and restate the verdict (a critical one means DO NOT SHIP).');
  }
  out.push('');
  return out.join('\n');
}

export { EXPLAIN };
