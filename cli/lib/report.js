// Every finding gets three plain-English answers: what is this, why does it
// matter, what do I do. If an explanation needs jargon, it gets rewritten.
const EXPLAIN = {
  'secret-in-code': {
    title: 'A secret key is written directly in your code',
    why: 'Anyone who sees this code — on GitHub, in a screenshot, in your deployed app — can use this key as you, and you get the bill.',
    fix: 'Move the value into your .env file and read it from an environment variable (`process.env.YOUR_KEY_NAME` in JavaScript, `os.environ["YOUR_KEY_NAME"]` in Python). Most frameworks (Next.js, Create React App, Django, Rails, and others) load .env automatically; plain Node.js does not — add `require(\'dotenv\').config()` at the top of your entry file (`npm install dotenv` first), or on Node 20+ run your app with `node --env-file=.env yourapp.js`. Then rotate the key: log in to the provider and generate a new one, because this one is burned.',
  },
  'secret-in-history': {
    title: 'A secret exists in your git history',
    why: 'Deleting a key from your code does not delete it from git — every past version stays downloadable. If this repo goes public, the old key goes public with it.',
    // The one fix that genuinely needs different instructions depending on
    // repo state — a static string here was the single biggest thing
    // blocking a real first-time user from ever reaching a clean verdict
    // (found via an independent fresh-eyes test, not assumed; a second
    // independent test — see the git-add/identity gaps and the "what
    // actually leaked" gap below — confirmed the fix worked and found the
    // next layer of rough edges).
    fix: (f) => {
      const seeIt = `(Want to see exactly what leaked? Run \`git show ${f.commit || '<commit>'} -- ${f.file || '<file>'}\`.)`;
      if (f.hasRemote) {
        return `Step 1 (does the actual protecting): rotate the key now — log in to whichever service issued it and generate a new one. Step 2 (cleanup): since this repo has already been pushed somewhere, deleting local history isn't enough — the old commit may still be out there too. Use a tool built for this: [git filter-repo](https://github.com/newren/git-filter-repo) (\`git filter-repo --path <file> --invert-paths\` removes a whole file from history) or [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) (simpler, made for exactly this). Either way you'll need to force-push afterward — if that sentence is unfamiliar, paste it into an AI chat or ask someone with git experience before running anything, since a force-push affects anyone else using this repo. ${seeIt}`;
      }
      return `Step 1 (does the actual protecting): rotate the key now — log in to whichever service issued it and generate a new one. Step 2 (cleanup, and the easy one): since this repo has never been pushed anywhere yet (no remote is configured), the simplest fix is to erase git's memory and start fresh — this keeps every file exactly as it is, it only forgets old commits. Run: \`rm -rf .git && git init && git add -A && git commit -m "start"\` (Mac/Linux; on Windows, delete the \`.git\` folder yourself first, then run \`git init && git add -A && git commit -m "start"\`). Two things git might print along the way, both harmless: a note about the default branch name (ignore it), or "Please tell me who you are" — if you see that, run the two \`git config --global user.email/user.name\` lines it shows you, then just run the \`git commit\` part again. ${seeIt}`;
    },
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
    fix: 'Add a line with just `.env` (and `.env.*`) to your .gitignore file — or run `shipclear ship` again without `--no-fix` and ShipClear will add it for you.',
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
    fix: 'Copy .env to .env.example and delete all the values, keeping just the variable names — or run `shipclear ship` again without `--no-fix` and ShipClear will create it for you.',
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

// `scan` deliberately skips slower checks (full git history, dependency
// audits — see checks.js's `quick` mode) so it can run instantly. Its
// verdict must never be visually or textually confusable with the real
// ship/no-ship call from the full gate — a quick scan saying "CLEARED TO
// SHIP" is exactly the false-GO failure mode this project treats as its
// worst case (see CONTRIBUTING.md). Found by an independent fresh-eyes
// test that ran `scan`, saw this exact banner, and nearly stopped there.
const QUICK_VERDICT_TEXT = {
  DO_NOT_SHIP: '🛑 Secrets found in this quick check — do not ship yet.',
  SHIP_WITH_FIXES: '🟡 Issues found in this quick check.',
  CLEARED: '✅ No secrets found in this quick check — but this is NOT the full gate.',
};

export const BADGE_MARKDOWN =
  '[![ShipClear: cleared to ship](https://img.shields.io/badge/ShipClear-cleared%20to%20ship-brightgreen)](https://github.com/adamtimmerberg/ShipClear)';

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

// Most fix texts are a plain string; secret-in-history's varies by repo
// state (see EXPLAIN above), so it's a function of the finding instead.
const fixTextFor = (ex, f) => (typeof ex.fix === 'function' ? ex.fix(f) : ex.fix);

export function renderTerminal({ findings, notes, verdict, fixes = [], version, quick = false }) {
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
    lines.push(`      what to do: ${fixTextFor(ex, f)}`);
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
  const v = quick ? QUICK_VERDICT_TEXT[verdict] : VERDICT_TEXT[verdict];
  lines.push('  ' + color(verdict === 'CLEARED' ? '32;1' : verdict === 'DO_NOT_SHIP' ? '31;1' : '33;1', v));
  // The badge claims "cleared to ship" — only the full gate has earned
  // that claim. Never offer it off the back of a quick, partial check.
  if (verdict === 'CLEARED' && !quick) {
    lines.push('');
    lines.push('  Show it off — add the badge to your README:');
    lines.push('  ' + BADGE_MARKDOWN);
  }
  lines.push('');
  lines.push(quick ? '  This was a quick check only. For the full gate: shipclear ship' : '  Full report written to SHIP-REPORT.md');
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
  if (verdict === 'CLEARED') {
    out.push('Cleared! Add the badge to your README to show your app passed:');
    out.push('');
    out.push('```markdown');
    out.push(BADGE_MARKDOWN);
    out.push('```');
    out.push('');
  }
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
      out.push(`- **What to do:** ${fixTextFor(ex, f)}`);
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
    out.push('- [ ] **Auth and ownership:** every endpoint either requires authentication or is intentionally public; every resource access verifies the resource belongs to the requester (an ID alone is never enough).');
    out.push('- [ ] **Database exposure:** no world-readable/world-writable rules (Firebase rules, Supabase RLS, etc.).');
    out.push('- [ ] **Client-side leakage:** no server secret reaches anything delivered to the browser.');
    out.push('- [ ] **Input handling:** database/shell input parameterized, rendered HTML escaped, file uploads validated with size limits.');
    out.push('- [ ] **Server-side trust:** prices, roles, and privileged fields computed or verified server-side; webhook signatures verified before processing.');
    out.push('- [ ] **Session and abuse surface:** tokens in httpOnly cookies (not localStorage); rate limiting on login/signup/reset.');
    out.push('- [ ] **Debug surface:** no debug endpoints, stack traces shown to users, or `*` CORS on authenticated APIs.');
    out.push('- [ ] **AI surface** (if the app calls LLMs/agents): prompt inputs treated as untrusted, model output validated before executing/rendering/storing, agent and MCP tools least-privilege.');
    out.push('- [ ] **Verdict update:** append any semantic findings here and restate the verdict (a critical one means DO NOT SHIP).');
    out.push('');
    out.push("Running ShipClear without an AI coding tool? Paste this checklist and your code into any AI chat (ChatGPT, Claude.ai, Gemini — even a free one) and ask it to work through the list — or ask a developer friend. These checks matter, but they need something that can read your code to answer them.");
  }
  out.push('');
  return out.join('\n');
}

export { EXPLAIN };
