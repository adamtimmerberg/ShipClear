// ShipClear test suite. Zero dependencies: copies each fixture into a temp
// git repo (renaming the `dot-` prefix to a real dot — see tests/fixtures),
// commits it, runs the gate, and asserts on the findings.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runGate } from '../cli/lib/checks.js';
import { applyFixes, resetHistory } from '../cli/lib/fix.js';
import { verdictOf, renderMarkdown, renderTerminal, VERDICT_TEXT, EXPLAIN } from '../cli/lib/report.js';
import { findSecrets, looksPlaceholder, personalPaths } from '../cli/lib/patterns.js';

const here = path.dirname(fileURLToPath(import.meta.url));
let passed = 0;
const failures = [];

function check(name, condition, detail = '') {
  if (condition) {
    passed++;
    console.log(`  ✔ ${name}`);
  } else {
    failures.push(name);
    console.error(`  ✘ ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

function copyFixture(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const name = entry.name.startsWith('dot-') ? '.' + entry.name.slice(4) : entry.name;
    const from = path.join(src, entry.name);
    const to = path.join(dest, name);
    if (entry.isDirectory()) copyFixture(from, to);
    else fs.copyFileSync(from, to);
  }
}

function makeRepo(fixture) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipclear-test-'));
  copyFixture(path.join(here, 'fixtures', fixture), dir);
  const git = (...args) =>
    execFileSync('git', ['-c', 'user.email=tests@shipclear.local', '-c', 'user.name=ShipClear Tests',
      '-c', 'commit.gpgsign=false', ...args], { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
  git('init', '-q', '-b', 'main');
  git('add', '-A', '-f');
  git('commit', '-q', '-m', 'fixture');
  return dir;
}

// Test vectors are concatenated at runtime so no secret-shaped literal ever
// exists in this file — otherwise ShipClear's own gate would (correctly!)
// flag it.
const FAKE_ANTHROPIC_KEY = 'sk-ant-' + 'FAKE12345678901234567890123456';

// --- unit: pattern behavior ---
console.log('\npatterns');
{
  const hits = findSecrets(`const k = "${FAKE_ANTHROPIC_KEY}";`);
  check('detects Anthropic key shape', hits.some((h) => h.patternId === 'anthropic-api-key'));
  check('overlapping match deduplicated (not also reported as OpenAI)',
    !hits.some((h) => h.patternId === 'openai-api-key'));

  check('placeholder values are recognized', looksPlaceholder('your-api-key-here'));
  check('generic matcher ignores placeholders',
    findSecrets('apiKey = "your-api-key-here-12345"').length === 0);
  check('generic matcher catches realistic values',
    findSecrets('apiKey = "q7x9' + 'Zk2pLm4vRn8tWc3y"').some((h) => h.patternId === 'generic-secret'));
  check('env var usage is not a finding', findSecrets('const key = process.env.API_KEY;').length === 0);
}

// --- unit: provider pattern vectors (every pattern proven, per CONTRIBUTING) ---
console.log('\nprovider vectors');
{
  // [patternId, vector] — all fakes assembled at runtime.
  const vectors = [
    ['aws-access-key', 'AKIA' + 'IOSFODNN7EXAMPLE'],
    ['stripe-live-key', 'sk_live_' + 'FAKEFAKEFAKEFAKEFAKE'],
    ['openrouter-api-key', 'sk-or-v1-' + 'ab12'.repeat(16)],
    ['openai-api-key', 'sk-proj-' + 'FAKE'.repeat(10)],
    ['github-token', 'ghp_' + 'A1b2C3'.repeat(6)],
    ['google-api-key', 'AIza' + 'FAKE0'.repeat(7)],
    ['slack-token', 'xoxb-' + '123456789-FAKEFAKE'],
    ['sendgrid-api-key', 'SG.' + 'a'.repeat(22) + '.' + 'b'.repeat(43)],
    ['npm-token', 'npm_' + 'a1B2'.repeat(9)],
    ['huggingface-token', 'hf_' + 'aB3d'.repeat(8) + 'aB'],
    ['digitalocean-token', 'dop_v1_' + 'ab12'.repeat(16)],
    ['groq-api-key', 'gsk_' + 'FAKE'.repeat(6)],
    ['xai-api-key', 'xai-' + 'FAKE'.repeat(6)],
    ['azure-account-key', 'AccountKey=' + 'Ab1+'.repeat(11) + '=='],
    ['private-key-block', '-----BEGIN ' + 'PRIVATE KEY-----'],
    ['connection-string', 'postgres://app:' + 'hunter2secret9@db.host/x'],
  ];
  for (const [id, vector] of vectors) {
    check(`detects ${id}`, findSecrets(`x = "${vector}"`, { includeGeneric: false })
      .some((h) => h.patternId === id));
  }
  // Supabase service-role JWT: payload decodes to role=service_role.
  const b64url = (s) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const srJwt = [b64url('{"alg":"HS256"}'), b64url('{"role":"service_role"}'), 'FAKESIGNATUREFAKE'].join('.');
  const anonJwt = [b64url('{"alg":"HS256"}'), b64url('{"role":"anon"}'), 'FAKESIGNATUREFAKE'].join('.');
  check('detects supabase service-role JWT',
    findSecrets(srJwt, { includeGeneric: false }).some((h) => h.patternId === 'supabase-service-role'));
  check('ignores supabase anon JWT (public by design)',
    findSecrets(anonJwt, { includeGeneric: false }).length === 0);
}

// --- unit: false-positive regressions (each vector found on a real repo) ---
console.log('\nfalse-positive regressions (from the real-world sweep)');
{
  check('template db password is not a finding (t3/taxonomy)',
    findSecrets('DATABASE_URL="mysql://root:password@localhost:3306/app"').length === 0);
  check('changethis db password is not a finding (fastapi-template)',
    findSecrets('postgres://postgres:changethis@db:5432/app').length === 0);
  check('mustache-templated password is not a finding (fastapi-template)',
    findSecrets('password: "{{ password }}"').length === 0);
  check('env() indirection is not a finding (supabase config.toml)',
    findSecrets('secret = "env(SUPABASE_AUTH_SECRET)"').length === 0);
  check('ALL_CAPS constant value is not a finding (firebase quickstart)',
    findSecrets('apiKey: "API_KEY_FROM_CONSOLE"').length === 0);
  check('real db password still IS a finding',
    findSecrets('postgres://app:q7x9' + 'Zk2pLm4vRn8t@db.host/x').length === 1);
  check('import path is not a personal path (precedent)',
    personalPaths('import Card from "components/home/card";').length === 0);
  check('absolute path still IS a personal path',
    personalPaths('const dir = "/home/adamdev/uploads";').length === 1);
  check('mypassword db password is not a finding (firebase quickstart)',
    findSecrets('postgresql://user:mypassword@localhost:5432/db').length === 0);
}

// --- integration: vulnerable fixture ---
console.log('\nvulnerable-app (every planted issue must be found)');
{
  const dir = makeRepo('vulnerable-app');
  const { findings } = runGate(dir);
  const ids = new Set(findings.map((f) => f.id));
  const expected = [
    'secret-in-code',      // OpenAI/AWS keys + connection string in source
    'secret-in-history',   // same secrets, via the committed history
    'env-tracked',         // .env is committed
    'key-file-tracked',    // deploy_key.pem is committed
    'env-example-leak',    // sk_live value in .env.example
    'gitignore-incomplete',// no .gitignore at all
    'pii-data-file',       // users.csv: 3 emails + SSNs
    'test-account',        // admin email + password123 pair
    'personal-path',       // /home/adamdev/... in config.js
    'agent-artifact',      // .claude/settings.local.json is committed
  ];
  for (const id of expected) check(`finds ${id}`, ids.has(id));
  check('verdict is DO NOT SHIP', verdictOf(findings) === 'DO_NOT_SHIP', `got ${verdictOf(findings)}`);

  const fixes = applyFixes(dir, findings);
  const gi = fs.readFileSync(path.join(dir, '.gitignore'), 'utf8');
  check('auto-fix repairs .gitignore', gi.includes('.env'));
  check('auto-fix also keeps the findings map (SHIP-REPORT.md) out of git', gi.includes('SHIP-REPORT.md'));
  check('auto-fix reported', fixes.length >= 1);
  check('gitignore finding marked resolved',
    findings.find((f) => f.id === 'gitignore-incomplete')?.resolved === true);
  check('verdict still DO NOT SHIP after safe fixes (criticals remain)',
    verdictOf(findings) === 'DO_NOT_SHIP');
  fs.rmSync(dir, { recursive: true, force: true });
}

// --- report text never claims a fix that wasn't applied ---
// (`ship --no-fix` leaves these findings unresolved; the fix-text is only
// ever shown in exactly that unresolved state, so it must never claim the
// fix already happened — a real bug this project shipped once.)
console.log('\nreport text (no false "already fixed" claims)');
{
  for (const id of ['gitignore-incomplete', 'env-example-missing']) {
    const finding = { id, severity: 'high', file: '.gitignore' };
    const md = renderMarkdown({ findings: [finding], notes: [], verdict: 'SHIP_WITH_FIXES', version: '0.0.0', semanticSection: false });
    check(`${id}: fix text doesn't falsely claim it's done`,
      !/ShipClear (fixed|created)/i.test(EXPLAIN[id].fix),
      EXPLAIN[id].fix);
    check(`${id}: rendered report doesn't falsely claim it's done`,
      !/ShipClear (fixed|created)/i.test(md));
  }
}

// --- secret-in-history: guidance must actually differ by repo state ---
// (a static "use git filter-repo or BFG" pointer was the single thing that
// stopped an independent fresh-eyes test from ever reaching a clean verdict
// — see the commit that added this. The no-remote case has a real,
// copy-pasteable easy path; the has-remote case still names real tools with
// a real example command instead of just naming them.)
console.log('\nsecret-in-history guidance (varies by repo state)');
{
  const noRemoteFix = EXPLAIN['secret-in-history'].fix({ hasRemote: false });
  const hasRemoteFix = EXPLAIN['secret-in-history'].fix({ hasRemote: true });
  check('no-remote case gives a concrete, runnable command',
    /rm -rf \.git && git init/.test(noRemoteFix));
  check('no-remote case never mentions force-push (not needed — nothing was ever pushed)',
    !/force-push/i.test(noRemoteFix));
  check('has-remote case names a real tool with a real example command',
    /git filter-repo --path/.test(hasRemoteFix));
  check('has-remote case warns about force-push',
    /force-push/i.test(hasRemoteFix));
  check('both cases lead with rotation as the action that actually protects you',
    /^Step 1.*rotate the key now/.test(noRemoteFix) && /^Step 1.*rotate the key now/.test(hasRemoteFix));

  // A second independent test verified the fix above actually worked, then
  // found the next layer: the no-remote command never mentioned `git add`
  // (so `git init` alone leaves nothing committed), and two unrelated git
  // prompts (branch-name hint, missing identity) weren't anticipated.
  check('no-remote case includes git add, not just init',
    /git add -A/.test(noRemoteFix));
  check('no-remote case warns about the "who you are" identity prompt',
    /Please tell me who you are|user\.email/.test(noRemoteFix));
  check('both cases point at how to actually see what leaked',
    /git show/.test(noRemoteFix) && /git show/.test(hasRemoteFix));
}

// --- integration: clean fixture ---
// --- scan's quick "cleared" must never look like ship's real verdict ---
// A second independent test ran `scan`, saw the exact same "CLEARED TO
// SHIP" banner `ship` gives after the FULL gate, and nearly stopped there
// — `scan` deliberately skips the git-history check, so that would have
// been a false all-clear. This is the "no false GO verdicts" rule from
// CONTRIBUTING.md, concretely violated and now concretely fixed.
console.log('\nquick scan verdict is never confusable with the full gate\'s');
{
  const args = { findings: [], notes: [], verdict: 'CLEARED', version: '0.0.0' };
  const full = renderTerminal(args);
  const quick = renderTerminal({ ...args, quick: true });
  check('full gate says CLEARED TO SHIP', full.includes(VERDICT_TEXT.CLEARED));
  check('quick scan does NOT say CLEARED TO SHIP', !quick.includes(VERDICT_TEXT.CLEARED));
  check('quick scan verdict text differs from the full gate\'s', full !== quick);
  check('quick scan never offers the ship-worthy badge', !quick.includes('add the badge'));
  check('full gate on a real CLEARED verdict does offer the badge', full.includes('add the badge'));
}

console.log('\nclean-app (no false alarms)');
{
  const dir = makeRepo('clean-app');
  const { findings } = runGate(dir);
  const open = findings.filter((f) => !f.resolved);
  check('no findings at all', open.length === 0,
    open.map((f) => `${f.id}@${f.file}`).join(', '));
  check('verdict is CLEARED', verdictOf(findings) === 'CLEARED');
  fs.rmSync(dir, { recursive: true, force: true });
}

// --- integration: deleted secret still found in history ---
console.log('\nhistory (deleting a secret does not un-leak it)');
{
  const dir = makeRepo('clean-app');
  const git = (...args) =>
    execFileSync('git', ['-c', 'user.email=tests@shipclear.local', '-c', 'user.name=ShipClear Tests',
      '-c', 'commit.gpgsign=false', ...args], { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
  const leaky = path.join(dir, 'oops.js');
  fs.writeFileSync(leaky, `const key = "${FAKE_ANTHROPIC_KEY}";\n`);
  git('add', 'oops.js');
  git('commit', '-q', '-m', 'add secret');
  fs.rmSync(leaky);
  git('add', '-A');
  git('commit', '-q', '-m', 'remove secret');

  const { findings } = runGate(dir);
  check('secret-in-history found after deletion',
    findings.some((f) => f.id === 'secret-in-history'));
  check('working tree itself is clean of secret-in-code',
    !findings.some((f) => f.id === 'secret-in-code'));
  check('verdict is DO NOT SHIP', verdictOf(findings) === 'DO_NOT_SHIP');
  fs.rmSync(dir, { recursive: true, force: true });
}

// --- --fix-history: the one destructive fix, opt-in, with guardrails ---
// The alternative was telling a first-time user to type `rm -rf .git` by
// hand, with nothing checking the directory, branches, or stashes. This
// runs on exactly the scanned folder and refuses wherever "start fresh"
// would silently destroy something a hand-typed command wouldn't notice.
console.log('\n--fix-history (safe automated history reset)');
{
  const gitIn = (dir) => (...args) =>
    execFileSync('git', ['-c', 'user.email=tests@shipclear.local', '-c', 'user.name=ShipClear Tests',
      '-c', 'commit.gpgsign=false', ...args], { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' });
  const leakyRepo = () => {
    const dir = makeRepo('clean-app');
    const git = gitIn(dir);
    fs.writeFileSync(path.join(dir, 'oops.js'), `const key = "${FAKE_ANTHROPIC_KEY}";\n`);
    git('add', 'oops.js'); git('commit', '-q', '-m', 'leak');
    fs.writeFileSync(path.join(dir, 'oops.js'), '// moved\n');
    git('add', 'oops.js'); git('commit', '-q', '-m', 'removed');
    return { dir, git };
  };

  // Happy path: no remote, one branch, no stash.
  {
    const { dir, git } = leakyRepo();
    const branchBefore = git('branch', '--show-current').trim();
    const { findings } = runGate(dir);
    check('setup: secret is in history before reset', findings.some((f) => f.id === 'secret-in-history'));
    const { done, refused } = resetHistory(dir, findings);
    check('reset ran (not refused)', !!done && !refused, refused);
    check('done message insists the key still needs rotating', /rotate the key/.test(done || ''));
    check('secret is gone from all history afterward',
      !git('log', '--all', '-p').includes(FAKE_ANTHROPIC_KEY));
    check('exactly one fresh commit remains', git('log', '--oneline').trim().split('\n').length === 1);
    check('branch name preserved (no silent main→master rename)',
      git('branch', '--show-current').trim() === branchBefore);
    check('history finding marked resolved',
      findings.filter((f) => f.id === 'secret-in-history').every((f) => f.resolved));
    check('a re-run gate is clean of history findings',
      !runGate(dir).findings.some((f) => f.id === 'secret-in-history'));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // When git already has an identity, no placeholder is set and none is
  // mentioned. Uses GIT_CONFIG_GLOBAL so the real global config is never
  // touched (the git helper inherits process.env).
  {
    const { dir, git } = leakyRepo();
    const fakeGlobal = path.join(dir, '.fake-gitconfig');
    fs.writeFileSync(fakeGlobal, '[user]\n\temail = real@person.test\n\tname = Real Person\n');
    const prev = process.env.GIT_CONFIG_GLOBAL;
    process.env.GIT_CONFIG_GLOBAL = fakeGlobal;
    try {
      const { findings } = runGate(dir);
      const { done } = resetHistory(dir, findings);
      check('with an existing git identity, no placeholder is set or mentioned',
        !!done && !/placeholder/.test(done));
      check('with an existing git identity, the fresh commit is authored as that person',
        git('log', '-1', '--format=%ae').trim() === 'real@person.test');
    } finally {
      if (prev === undefined) delete process.env.GIT_CONFIG_GLOBAL; else process.env.GIT_CONFIG_GLOBAL = prev;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // Refusals: each must leave .git and the history completely untouched.
  const refuses = [
    ['a remote is configured', (git) => git('remote', 'add', 'origin', 'https://example.com/x.git'), /remote/],
    ['a second branch exists', (git) => git('branch', 'feature'), /2 branches/],
    ['there are stashed changes', (git, dir) => { fs.writeFileSync(path.join(dir, 'wip.txt'), 'wip\n'); git('add', 'wip.txt'); git('stash', '-q'); }, /stash/],
  ];
  for (const [why, setup, reason] of refuses) {
    const { dir, git } = leakyRepo();
    setup(git, dir);
    const before = git('log', '--all', '--oneline');
    const { findings } = runGate(dir);
    const { done, refused } = resetHistory(dir, findings);
    check(`refuses when ${why}`, !done && reason.test(refused || ''), refused);
    check(`history untouched when ${why}`, git('log', '--all', '--oneline') === before);
    check(`finding stays unresolved when ${why}`,
      findings.some((f) => f.id === 'secret-in-history' && !f.resolved));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// --- CLI smoke test ---
console.log('\ncli');
{
  const out = execFileSync('node', [path.join(here, '../cli/bin/shipclear.js'), '--version'], { encoding: 'utf8' });
  check('--version prints a version', /^\d+\.\d+\.\d+$/.test(out.trim()), out.trim());

  // --help / -h / help are the first thing anyone confused tries — they
  // must succeed cleanly, not print help text and THEN report themselves
  // as an unknown command (a real regression this project shipped once).
  const bin = path.join(here, '../cli/bin/shipclear.js');
  for (const flag of ['--help', '-h', 'help']) {
    const r = spawnSync('node', [bin, flag], { encoding: 'utf8' });
    check(`\`shipclear ${flag}\` exits 0`, r.status === 0, `exit ${r.status}`);
    check(`\`shipclear ${flag}\` doesn't call itself unknown`,
      !r.stdout.includes('Unknown command') && !(r.stderr || '').includes('Unknown command'));
  }

  // A filesystem error mid-command must produce a plain-English message,
  // never a raw Node stack trace — a real crash this project shipped once
  // (found by testing a read-only directory; reproduced here portably
  // across OSes with a `.gitignore` that's a directory instead of a file,
  // since chmod-based permission tricks aren't reliable on Windows CI).
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipclear-crash-test-'));
    fs.mkdirSync(path.join(dir, '.gitignore'));
    const r = spawnSync('node', [bin, 'setup'], { cwd: dir, encoding: 'utf8' });
    check('a filesystem error during setup exits non-zero', r.status !== 0);
    check('a filesystem error shows a plain message, not a stack trace',
      /ShipClear hit an unexpected problem/.test(r.stderr) && !/at Object\.|at cmdSetup|node:fs:/.test(r.stderr),
      r.stderr.slice(0, 200));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

console.log(`\n${passed} passed, ${failures.length} failed\n`);
if (failures.length) process.exit(1);
