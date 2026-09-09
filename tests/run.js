// ShipClear test suite. Zero dependencies: copies each fixture into a temp
// git repo (renaming the `dot-` prefix to a real dot — see tests/fixtures),
// commits it, runs the gate, and asserts on the findings.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runGate } from '../cli/lib/checks.js';
import { applyFixes } from '../cli/lib/fix.js';
import { verdictOf, renderMarkdown, EXPLAIN } from '../cli/lib/report.js';
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
  check('auto-fix repairs .gitignore', fs.readFileSync(path.join(dir, '.gitignore'), 'utf8').includes('.env'));
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

// --- integration: clean fixture ---
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
}

console.log(`\n${passed} passed, ${failures.length} failed\n`);
if (failures.length) process.exit(1);
