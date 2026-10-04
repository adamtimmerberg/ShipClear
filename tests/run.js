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
import { githubSlug, badgeMarkdown, withBadge, workflowYaml, installBadge, WORKFLOW_REL } from '../cli/lib/badge.js';

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

// --- unit: certificate checking switched off ---
// The prevention rules forbid it by name; it's a literal string, so the
// deterministic layer must catch it. Vectors assembled at runtime so this
// file doesn't trip the self-gate.
console.log('\ntls verification off');
{
  const { TLS_VERIFICATION_OFF } = await import('../cli/lib/patterns.js');
  const hits = (s) => { TLS_VERIFICATION_OFF.lastIndex = 0; return TLS_VERIFICATION_OFF.test(s); };
  const ru = 'reject' + 'Unauthorized';
  // Descriptions and vectors avoid the literal matchable forms — the gate
  // scans this file, and only tests/fixtures is exempt.
  const vFalse = 'verify=' + 'False';
  check('catches the Node reject-unauthorized flag set false', hits(`new https.Agent({ ${ru}: false })`));
  check('catches the NODE_TLS env override set to 0', hits('process.env.NODE_TLS_' + 'REJECT_UNAUTHORIZED = "0";'));
  check('catches the Python verify flag set false', hits(`requests.get(url, ${vFalse})`));
  check('does not flag the reject-unauthorized flag set true', !hits(`new https.Agent({ ${ru}: true })`));
  check('does not flag the Python verify flag set true', !hits('requests.get(url, ' + 'verify=True)'));
}

// --- unit: framework debug mode on ---
// Real gap found by the first Python-project test — the audience isn't
// only Node. Scoped to the dangerous form (Flask app.run debug=True /
// FLASK_DEBUG), not Django's DEBUG=True dev default.
console.log('\ndebug mode on');
{
  const { DEBUG_MODE_ON } = await import('../cli/lib/patterns.js');
  const hits = (s) => { DEBUG_MODE_ON.lastIndex = 0; return DEBUG_MODE_ON.test(s); };
  // Build the dangerous token at runtime so no matchable literal sits in
  // this scanned file (the pattern's [^)]* would otherwise span a naive
  // '+' concatenation — see the debug self-flag fix in the log).
  const on = 'debug' + '=' + 'True';
  const flaskFlag = 'FLASK_' + 'DEBUG' + '=1';
  check('catches a Flask app.run call in debug mode', hits(`app.run(${on})`));
  check('catches app.run with host arg then debug on', hits(`app.run(host="0.0.0.0", ${on})`));
  check('catches the FLASK_DEBUG env flag', hits(flaskFlag));
  check('does not flag debug turned off', !hits('app.run(' + 'debug=False)'));
  check('does not flag a plain debug variable', !hits('const ' + 'debug = someValue;'));
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
    personalPaths('const dir = "/home/' + 'adamdev/uploads";').length === 1);
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
    'personal-path',       // an absolute home path in config.js
    'agent-artifact',      // .claude/settings.local.json is committed
    'tls-verification-off',// disabled cert check in server.js
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
    /git filter-repo --(replace-text|path)/.test(hasRemoteFix));
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

  // git-filter-repo is not part of git; a real user has to install it. The
  // has-remote text must say how, give the full command sequence including
  // re-adding the remote (filter-repo strips it) and the force-push, and
  // offer the "ask your AI" hand-off — and it must say the user is already
  // safe once the key is rotated, so a hard cleanup step never reads as
  // "you are still exposed."
  const hasRemoteWithFile = EXPLAIN['secret-in-history'].fix({ hasRemote: true, file: 'bot.js', commit: 'abc1234' });
  check('has-remote case says how to install filter-repo', /(pipx|pip) install .*git-filter-repo/.test(hasRemoteWithFile));
  // A secret INSIDE a code file: scrub the value, keep the file. Telling
  // the user to --invert-paths their main source file would delete it.
  check('has-remote, code file: scrubs the value with --replace-text',
    /--replace-text/.test(hasRemoteWithFile) && !/--path bot\.js --invert-paths/.test(hasRemoteWithFile));
  check('has-remote, code file: never prints the secret, tells the user where to copy it from',
    /copy it from the `git show`/.test(hasRemoteWithFile));
  check('has-remote, code file: says to delete the expressions file afterward',
    /delete `secrets-to-remove\.txt`/.test(hasRemoteWithFile));
  // A whole-secrets file (.env, .pem): removing the file from history IS right.
  const hasRemoteEnv = EXPLAIN['secret-in-history'].fix({ hasRemote: true, file: '.env', commit: 'abc1234' });
  check('has-remote, .env: removes the whole file with --invert-paths',
    /--path \.env --invert-paths/.test(hasRemoteEnv) && !/--replace-text/.test(hasRemoteEnv));
  // `git push --force origin main` fails outright for a user on master.
  const hasRemoteMaster = EXPLAIN['secret-in-history'].fix({ hasRemote: true, file: 'bot.js', commit: 'abc1234', branch: 'master' });
  check('has-remote: force-push uses the user\'s actual branch name',
    /git push --force origin master/.test(hasRemoteMaster) && !/origin main/.test(hasRemoteMaster));
  // Round 4: after cleaning the remote with a mirror-based tool (BFG), the
  // user's own folder still had the old history and `ship` re-reported the
  // same CRITICAL; the only git word she knew (pull) produced three fatals.
  check('has-remote: says how to check filter-repo is installed', /git filter-repo --version/.test(hasRemoteMaster));
  check('has-remote: gives a pip fallback for externally-managed-environment', /pipx install|externally-managed/.test(hasRemoteMaster));
  check('has-remote: after a BFG cleanup, tells the user to reset their own folder to the cleaned remote',
    /git fetch && git reset --hard origin\/master/.test(hasRemoteMaster));
  check('has-remote: says to re-run ship to confirm', /`shipclear ship` again to confirm/.test(hasRemoteMaster));
  check('has-remote: warns what a BFG failure looks like', /Caused by:/.test(hasRemoteMaster));
  check('has-remote: notes GitHub may keep the old commit reachable for a while', /reachable by its ID/.test(hasRemoteMaster));
  check('has-remote: the AI hand-off sentence matches the file type',
    /scrub that value.*keep the file/.test(hasRemoteWithFile) && /remove that file from every commit/.test(hasRemoteEnv));
  check('has-remote case covers re-adding the remote and the force-push',
    /git remote add origin/.test(hasRemoteWithFile) && /git push --force/.test(hasRemoteWithFile));
  check('has-remote case offers a paste-able ask for the AI assistant', /Paste it: /.test(hasRemoteWithFile));
  check('has-remote case says rotation alone already makes you safe', /already safe/.test(hasRemoteWithFile));
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
  check('quick scan never offers the ship-worthy badge', !quick.includes('shipclear badge'));
  check('full gate on a real CLEARED verdict does offer the badge', full.includes('shipclear badge'));
  // Round 4: "scan said Nice, ship said CRITICAL thirty seconds later" —
  // the quick verdict must say what it doesn't look at, not just that it's partial.
  check('quick scan CLEARED says what it skipped', /current files only, not git history/.test(quick));

  // A stuck first-timer gets the troubleshooting link at the verdict when
  // there are findings, and is NOT nagged with it on a clean pass.
  const withFinding = renderTerminal({
    findings: [{ id: 'gitignore-incomplete', severity: 'high', file: '.gitignore' }],
    notes: [], verdict: 'SHIP_WITH_FIXES', version: '0.0.0',
  });
  check('a report with findings links to troubleshooting', /troubleshooting\.md/.test(withFinding));
  check('a clean CLEARED report does not nag with the troubleshooting link', !/troubleshooting\.md/.test(full));
}

// --- setup tells a beginner to commit what it created ---
// (Round 4: .gitignore and .env.example sat uncommitted the whole session;
// "commit" is not an instruction to someone who has never run git.)
console.log('\nsetup');
{
  const bin = path.join(here, '../cli/bin/shipclear.js');
  const dir = makeRepo('clean-app');
  // clean-app ships a .gitignore that already covers .env; drop it so the
  // gitignore step actually runs and its wording is exercised.
  fs.rmSync(path.join(dir, '.gitignore'));
  const r = spawnSync('node', [bin, 'setup'], { cwd: dir, encoding: 'utf8' });
  check('setup exits 0 in a git repo', r.status === 0, r.stderr);
  check('setup gives the literal commit command for the files it created',
    /git add -A && git commit -m/.test(r.stdout));
  check('setup explains gitignore protects future commits, and that ship finds earlier ones',
    /protects future commits/.test(r.stdout) && /`shipclear ship` will find it/.test(r.stdout));
  fs.rmSync(dir, { recursive: true, force: true });
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

  // The reset must run LAST. A third independent test ran it first, then
  // fixed the PII file and hardcoded login in the working tree — and got
  // CLEARED TO SHIP on a repo whose only commit still held four SSNs,
  // because the fresh start had snapshotted them. It must refuse while
  // any medium+ finding it can't itself cure is still open.
  {
    const { dir, git } = leakyRepo();
    fs.writeFileSync(path.join(dir, 'people.csv'),
      'name,email,ssn\nA B,ab1@gmail.com,123-45-6789\nC D,cd2@yahoo.com,987-65-4321\nE F,ef3@outlook.com,555-12-3456\n');
    git('add', 'people.csv'); git('commit', '-q', '-m', 'add data');
    const { findings } = runGate(dir);
    check('setup: both history and PII findings are open',
      findings.some((f) => f.id === 'secret-in-history') && findings.some((f) => f.id === 'pii-data-file'));
    const before = git('log', '--all', '--oneline');
    const { done, refused } = resetHistory(dir, findings);
    check('refuses while a PII finding is still open', !done && /people\.csv/.test(refused || ''), refused);
    check('says to fix those first and run it last', /fix those first.*last/i.test(refused || ''));
    check('history untouched when refused for open findings', git('log', '--all', '--oneline') === before);
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // rm -rf .git takes the commit guard with it. The same test found the
  // guard silently gone afterward — "secrets can no longer be committed"
  // was no longer true and nothing said so.
  {
    const { dir, git } = leakyRepo();
    const hookPath = path.join(dir, '.git', 'hooks', 'pre-commit');
    fs.mkdirSync(path.dirname(hookPath), { recursive: true });
    fs.writeFileSync(hookPath, '#!/bin/sh\n# ShipClear guard\nexit 0\n', { mode: 0o755 });
    const { findings } = runGate(dir);
    const { done } = resetHistory(dir, findings);
    check('reset succeeded with guard present', !!done);
    check('commit guard reinstalled after reset',
      fs.existsSync(hookPath) && fs.readFileSync(hookPath, 'utf8').includes('ShipClear'));
    check('done message says the guard was reinstalled', /guard was reinstalled/.test(done || ''));
    check('fresh commit message does not advertise the leak',
      !/leak|secret/i.test(git('log', '-1', '--format=%s')));
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

// --- the git commit guard: closed on findings, open when it can't run ---
// The third independent test hit a reinstalled hook that couldn't reach the
// (unpublished) package and got a wall of "npm error 404" blocking every
// commit, with no ShipClear-worded explanation. Same fail-open rule as the
// Claude Code guard: block only when the scan ran and found something.
console.log('\ngit commit guard');
{
  const { HOOK_SCRIPT, installHook } = await import('../cli/lib/fix.js');
  check('hook script blocks only on a real "ShipClear blocked" result',
    /ShipClear blocked/.test(HOOK_SCRIPT) && /Letting this commit through/.test(HOOK_SCRIPT));

  if (process.platform === 'win32') {
    console.log('  (skipped live hook run on Windows — `-x` under Git\'s sh is not reliable there; Linux/macOS cover it)');
  } else {
    const gitIn = (dir) => (...args) =>
      spawnSync('git', ['-c', 'user.email=tests@shipclear.local', '-c', 'user.name=ShipClear Tests',
        '-c', 'commit.gpgsign=false', ...args], { cwd: dir, encoding: 'utf8' });
    const dir = makeRepo('clean-app');
    const git = gitIn(dir);
    // A local ./node_modules/.bin/shipclear so the hook takes the "installed"
    // branch and runs THIS checkout, not npx.
    const bin = path.join(dir, 'node_modules', '.bin');
    fs.mkdirSync(bin, { recursive: true });
    fs.writeFileSync(path.join(bin, 'shipclear'),
      `#!/bin/sh\nexec node "${path.join(here, '../cli/bin/shipclear.js')}" "$@"\n`, { mode: 0o755 });
    check('installHook installs the guard', installHook(dir));

    fs.writeFileSync(path.join(dir, 'leak.js'), `const k = "${FAKE_ANTHROPIC_KEY}";\n`);
    git('add', 'leak.js');
    const blocked = git('commit', '-q', '-m', 'leak');
    check('a commit with a staged secret is blocked', blocked.status !== 0);
    check('the block is explained in ShipClear\'s words', /ShipClear blocked/.test(blocked.stderr));

    git('rm', '-q', '--cached', 'leak.js'); fs.rmSync(path.join(dir, 'leak.js'));
    fs.writeFileSync(path.join(dir, 'ok.txt'), 'ok\n');
    git('add', 'ok.txt');
    check('a clean commit goes through', git('commit', '-q', '-m', 'ok').status === 0);

    // Scanner unavailable → warn and let it through, never a wall of npm errors.
    fs.writeFileSync(path.join(bin, 'shipclear'), '#!/bin/sh\necho "npm error 404 Not Found" >&2\nexit 1\n', { mode: 0o755 });
    fs.writeFileSync(path.join(dir, 'more.txt'), 'more\n');
    git('add', 'more.txt');
    const open = git('commit', '-q', '-m', 'more');
    check('when the scanner cannot run, the commit is let through', open.status === 0);
    check('…with a ShipClear-worded warning, not raw npm output', /ShipClear guard: could not run/.test(open.stderr));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// --- the test-account registry the prevention rules point at ---
// core/prevention.md tells the AI to keep generated test logins in
// .shipclear/test-accounts.json "git-ignored" — so the gitignore block has
// to actually ignore it, a tracked copy has to be a finding, and the
// JSON shape it'd be written in has to match the hardcoded-login check.
console.log('\ntest-account registry');
{
  const { GITIGNORE_BLOCK } = await import('../cli/lib/fix.js');
  const { PASSWORD_ASSIGNMENT, SUSPICIOUS_ACCOUNT_EMAIL } = await import('../cli/lib/patterns.js');
  check('gitignore block ignores .shipclear/', /^\.shipclear\/$/m.test(GITIGNORE_BLOCK));
  // Assembled at runtime so this file never contains a login-shaped pair
  // itself (the self-gate scans tests/run.js — only fixtures/ is ignored).
  const adminEmail = 'admin@' + 'app.test';
  const pw = 'pass' + 'word';
  const jsonPair = `{ "email": "${adminEmail}", "${pw}": "letmein1" }`;
  const objPair = `{ email: '${adminEmail}', ${pw}: 'letmein1' }`;
  check('JSON-shaped "password": "…" matches the hardcoded-login check', PASSWORD_ASSIGNMENT.test(jsonPair));
  check('unquoted password: "…" still matches', PASSWORD_ASSIGNMENT.test(objPair));
  // Short password variable names an AI sometimes uses (missed on a monorepo
  // test until the pattern was broadened).
  check('pwd = "…" matches', PASSWORD_ASSIGNMENT.test('pwd = ' + '"letmein123"'));
  check('PW = "…" is deliberately NOT matched (too ambiguous/short)',
    !PASSWORD_ASSIGNMENT.test('PW = ' + '"letmein123"'));
  check('quoted admin email still matches', SUSPICIOUS_ACCOUNT_EMAIL.test(`"email": "${adminEmail}"`));

  // Real-world find: a genuine, unprompted AI coding session (not a
  // scripted fixture) built a waitlist app and gated /admin with exactly
  // this shape — a bare username, no email at all, "overridable" via env
  // but shipping a real hardcoded default. The original patterns required
  // an email for the account signal and direct adjacency for the password
  // signal, so this slipped through to a false CLEARED TO SHIP.
  const envFallbackUser = 'const ADMIN_USER = process.env.ADMIN_USER || ' + '"admin";';
  const envFallbackPw = 'const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || ' + '"launchpad";';
  check('bare "admin" username via env-fallback is an account signal (no email needed)',
    SUSPICIOUS_ACCOUNT_EMAIL.test(envFallbackUser));
  check('password via the same env-fallback idiom is a password signal',
    PASSWORD_ASSIGNMENT.test(envFallbackPw));
  check('a bare literal with no account-holder identifier nearby is NOT a signal on its own',
    !SUSPICIOUS_ACCOUNT_EMAIL.test('const ROLE_DEFAULT = ' + '"admin";'));

  // Same find, exercised end-to-end through the real gate (a real git repo,
  // a real file, runGate) rather than just the two regexes in isolation —
  // this is what actually shipped as a false CLEARED TO SHIP, so it's what
  // must stay caught.
  {
    const realDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipclear-realworld-'));
    const realGit = (...args) =>
      execFileSync('git', ['-c', 'user.email=tests@shipclear.local', '-c', 'user.name=ShipClear Tests',
        '-c', 'commit.gpgsign=false', ...args], { cwd: realDir, stdio: ['ignore', 'pipe', 'pipe'] });
    fs.writeFileSync(path.join(realDir, 'server.js'),
      `${envFallbackUser}\n${envFallbackPw}\nfunction requireAdmin() {}\n`);
    realGit('init', '-q', '-b', 'main');
    realGit('add', 'server.js');
    realGit('commit', '-q', '-m', 'add admin gate');
    const realFindings = runGate(realDir).findings;
    check('the real generated app\'s admin gate is caught end-to-end',
      realFindings.some((f) => f.id === 'test-account' && f.file === 'server.js'));
    check('the real generated app is no longer falsely CLEARED',
      verdictOf(realFindings) !== 'CLEARED');
    fs.rmSync(realDir, { recursive: true, force: true });
  }

  const dir = makeRepo('clean-app');
  const gitIn = (...args) =>
    execFileSync('git', ['-c', 'user.email=tests@shipclear.local', '-c', 'user.name=ShipClear Tests',
      '-c', 'commit.gpgsign=false', ...args], { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
  fs.mkdirSync(path.join(dir, '.shipclear'));
  fs.writeFileSync(path.join(dir, '.shipclear', 'test-accounts.json'), `[${jsonPair}]\n`);
  gitIn('add', '-f', '.shipclear/test-accounts.json'); gitIn('commit', '-q', '-m', 'oops');
  const { findings } = runGate(dir);
  check('a tracked .shipclear/test-accounts.json is a test-account finding',
    findings.some((f) => f.id === 'test-account' && f.file === '.shipclear/test-accounts.json'));
  fs.rmSync(dir, { recursive: true, force: true });

  // Untracked (as the rules intend): the gate still reminds the user at
  // launch time that these logins exist — without touching the verdict.
  const dir2 = makeRepo('clean-app');
  fs.mkdirSync(path.join(dir2, '.shipclear'));
  fs.writeFileSync(path.join(dir2, '.shipclear', 'test-accounts.json'), `[${jsonPair}]\n`);
  const r2 = runGate(dir2);
  check('an untracked registry yields an info reminder',
    r2.findings.some((f) => f.id === 'test-registry-present' && f.severity === 'info'));
  check('…that does not change the verdict', verdictOf(r2.findings) === 'CLEARED');
  check('…and is not mistaken for a committed one',
    !r2.findings.some((f) => f.id === 'test-account'));
  fs.rmSync(dir2, { recursive: true, force: true });
}

// --- the AI adapters must not run the destructive fix unasked ---
// The Claude Code /safe-to-ship command tells an agent to run ship and act
// on the report. Nothing else would stop it from running --fix-history for
// the user; that decision must stay human.
console.log('\nadapters');
{
  const cmd = fs.readFileSync(path.join(here, '../adapters/claude-code/commands/safe-to-ship.md'), 'utf8');
  const generic = fs.readFileSync(path.join(here, '../adapters/generic/INSTRUCTIONS.md'), 'utf8');
  check('/safe-to-ship tells the agent never to run --fix-history unasked',
    /Never run `shipclear ship --fix-history` on the user's behalf/.test(cmd));
  check('generic instructions carry the same rule',
    /Never run `shipclear ship --fix-history` on the user's behalf/.test(generic));
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

// --- the README badge ---
// A badge is a security claim, so it is held to the verdict's standard: it
// must never read green for code nobody checked. These tests pin the three
// things that guarantee that — the badge is a live workflow status, the
// workflow grades the commit as pushed (--no-fix) and only on a full
// CLEARED (--strict) — plus the placement bug found by running the command
// on this very repo.
console.log('\nbadge');
{
  const bin = path.join(here, '../cli/bin/shipclear.js');

  const newRepo = (name) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), `shipclear-badge-${name}-`));
    execFileSync('git', ['init', '-q', '-b', 'main', '.'], { cwd: dir });
    execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: dir });
    execFileSync('git', ['config', 'user.name', 'Test'], { cwd: dir });
    return dir;
  };

  // --- slug parsing: every remote form a real user might have ---
  for (const [url, want] of [
    ['https://github.com/o/r.git', 'o/r'],
    ['https://github.com/o/r', 'o/r'],
    ['git@github.com:o/r.git', 'o/r'],
    ['ssh://git@github.com/o/r.git', 'o/r'],
  ]) {
    const dir = newRepo('slug');
    execFileSync('git', ['remote', 'add', 'origin', url], { cwd: dir });
    const slug = githubSlug(dir);
    check(`githubSlug reads ${url}`, slug && `${slug.owner}/${slug.repo}` === want,
      JSON.stringify(slug));
    fs.rmSync(dir, { recursive: true, force: true });
  }
  {
    const dir = newRepo('nongh');
    execFileSync('git', ['remote', 'add', 'origin', 'https://gitlab.com/o/r.git'], { cwd: dir });
    check('githubSlug returns null for a non-GitHub remote', githubSlug(dir) === null);
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // --- the badge must be a live status, never a hardcoded color ---
  const badge = badgeMarkdown({ owner: 'o', repo: 'r', branch: 'main' });
  check('the badge points at the ShipClear workflow run',
    badge.includes('/actions/workflows/shipclear.yml/badge.svg'), badge);
  check('the badge is scoped to the branch and to pushed code',
    badge.includes('branch=main') && badge.includes('event=push'), badge);
  check('the badge carries no hardcoded color', !/brightgreen|-green\)|shields\.io\/badge\//.test(badge), badge);

  // --- placement ---
  check('an existing static badge is replaced in place',
    withBadge('# App\n\n[![ShipClear: cleared to ship](https://img.shields.io/badge/ShipClear-cleared%20to%20ship-brightgreen)](https://x)\n', badge)
      .text.includes(badge));
  check('the retired static badge does not survive the replacement',
    !withBadge('# App\n\n[![ShipClear: cleared to ship](https://img.shields.io/badge/ShipClear-cleared%20to%20ship-brightgreen)](https://x)\n', badge)
      .text.includes('shields.io/badge/ShipClear'));
  check('an existing badge row is joined, not disturbed', (() => {
    const r = withBadge('# App\n\n[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)\n\nprose\n', badge);
    return r.text.includes(badge) && r.text.includes('[![MIT]');
  })());
  check('with no badge row the badge goes under the title',
    withBadge('# App\n\nprose\n', badge).text.startsWith('# App\n\n' + badge));
  check('with no title at all the badge goes to the top',
    withBadge('just prose\n', badge).text.startsWith(badge));
  check('re-running leaves the README untouched',
    withBadge('# App\n\n' + badge + '\n', badge).changed === false);

  // The matcher used to be a "shipclear" substring search, which in this
  // repo matched github.com/adamtimmerberg/ShipClear in EVERY badge URL and
  // replaced the CI badge instead of adding ours. Found by running
  // `shipclear badge` on this project's own README.
  {
    const ci = '[![CI](https://github.com/someone/shipclear-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/someone/shipclear-tools)';
    const r = withBadge(`# Tools\n\n${ci}\n`, badge);
    check('a repo whose name contains "shipclear" keeps its other badges',
      r.text.includes(ci) && r.text.includes(badge), r.text);
  }

  // --- the generated workflow carries the whole guarantee ---
  const yaml = workflowYaml();
  check('the generated workflow grades the commit as pushed (--no-fix)', yaml.includes('--no-fix'));
  check('the generated workflow only passes on CLEARED (--strict)', yaml.includes('--strict'));
  check('the generated workflow fetches full history for the history scan',
    yaml.includes('fetch-depth: 0'));
  check('the generated workflow runs on every push', /^on:\n  push:/m.test(yaml));
  check('the generated workflow is named for the badge label', /^name: ShipClear$/m.test(yaml));

  // This repo's own workflow is what its own badge reports. If either flag
  // were ever dropped from it, this project's badge could show green for a
  // repo that did not fully clear — the exact failure it warns users about.
  {
    const own = fs.readFileSync(path.join(here, '../.github/workflows/shipclear.yml'), 'utf8');
    check("ShipClear's own badge workflow uses --no-fix --strict",
      /ship --no-fix --strict/.test(own));
  }

  // --- the command, end to end ---
  {
    const dir = newRepo('cmd');
    fs.writeFileSync(path.join(dir, 'README.md'), '# LaunchPad\n\nMy app.\n');
    fs.writeFileSync(path.join(dir, 'app.js'), 'console.log("hi");\n');
    execFileSync('git', ['add', '-A'], { cwd: dir });
    execFileSync('git', ['commit', '-qm', 'init'], { cwd: dir });

    // No remote: a live badge has nothing to report on, so it must refuse
    // rather than write a badge that can never turn green.
    const noRemote = spawnSync('node', [bin, 'badge'], { cwd: dir, encoding: 'utf8' });
    check('badge refuses without a GitHub remote', noRemote.status === 1, `exit ${noRemote.status}`);
    check('badge explains how to get a remote', /remote add origin/.test(noRemote.stderr));
    check('badge writes no workflow when it refuses',
      !fs.existsSync(path.join(dir, WORKFLOW_REL)));

    execFileSync('git', ['remote', 'add', 'origin', 'https://github.com/someone/launchpad.git'], { cwd: dir });
    const r = spawnSync('node', [bin, 'badge'], { cwd: dir, encoding: 'utf8' });
    check('badge succeeds once there is a GitHub remote', r.status === 0, r.stderr);
    check('badge writes the workflow', fs.existsSync(path.join(dir, WORKFLOW_REL)));
    check('badge puts the badge in the README',
      fs.readFileSync(path.join(dir, 'README.md'), 'utf8')
        .includes('someone/launchpad/actions/workflows/shipclear.yml/badge.svg'));
    check('badge says the badge reads "no status" until the first run',
      /no status/.test(r.stdout));

    // Second run must not duplicate anything.
    spawnSync('node', [bin, 'badge'], { cwd: dir, encoding: 'utf8' });
    const readme = fs.readFileSync(path.join(dir, 'README.md'), 'utf8');
    check('badge is idempotent', readme.split('shipclear.yml/badge.svg').length - 1 === 1);
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // An existing workflow is never overwritten — but one missing the flags
  // would let the badge read green for a repo that only partly cleared, so
  // it has to be called out rather than left as a quiet lie.
  {
    const dir = newRepo('existing');
    fs.writeFileSync(path.join(dir, 'README.md'), '# App\n');
    fs.mkdirSync(path.join(dir, '.github/workflows'), { recursive: true });
    const theirs = 'name: ShipClear\non: push\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npx shipclear ship\n';
    fs.writeFileSync(path.join(dir, WORKFLOW_REL), theirs);
    execFileSync('git', ['remote', 'add', 'origin', 'https://github.com/o/r.git'], { cwd: dir });
    const res = installBadge(dir);
    check('an existing workflow is left exactly as it was',
      fs.readFileSync(path.join(dir, WORKFLOW_REL), 'utf8') === theirs);
    check('an existing workflow missing the flags is called out',
      res.warnings.some((w) => /--no-fix --strict/.test(w)), JSON.stringify(res.warnings));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // --- --strict: the exit code the badge is computed from ---
  // Plain `ship` exits 0 on SHIP WITH FIXES, because a human reads the
  // report and decides. A badge cannot read, so --strict must fail there.
  {
    const dir = newRepo('strict-high');
    fs.writeFileSync(path.join(dir, 'app.js'), 'console.log(1);\n');
    fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n');
    fs.writeFileSync(path.join(dir, '.env'), 'API_TOKEN=' + 'placeholder-value-1234\n');
    execFileSync('git', ['add', 'app.js', '.gitignore'], { cwd: dir });
    execFileSync('git', ['commit', '-qm', 'init'], { cwd: dir });

    const plain = spawnSync('node', [bin, 'ship', '--no-fix'], { cwd: dir, encoding: 'utf8' });
    check('plain ship still exits 0 on SHIP WITH FIXES', plain.status === 0, plain.stdout);
    check('that repo really does have an unresolved HIGH finding',
      /SHIP WITH FIXES/.test(plain.stdout), plain.stdout);

    const strict = spawnSync('node', [bin, 'ship', '--no-fix', '--strict'], { cwd: dir, encoding: 'utf8' });
    check('--strict exits 1 on SHIP WITH FIXES', strict.status === 1, `exit ${strict.status}`);
    check('--strict says why it failed', /--strict: failing/.test(strict.stdout));

    // The other half of the guarantee: without --no-fix the run repairs its
    // own checkout and reports the repaired copy as CLEARED — a green badge
    // for a commit that was pushed with the finding still in it.
    const fixing = spawnSync('node', [bin, 'ship', '--strict'], { cwd: dir, encoding: 'utf8' });
    check('--strict alone can still clear by fixing its own checkout (why the workflow uses --no-fix)',
      fixing.status === 0 && /CLEARED/.test(fixing.stdout), `exit ${fixing.status}`);
    fs.rmSync(dir, { recursive: true, force: true });
  }
  {
    const dir = newRepo('strict-clean');
    fs.writeFileSync(path.join(dir, 'app.js'), 'console.log(1);\n');
    fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n.env.*\n!.env.example\nSHIP-REPORT.md\n');
    execFileSync('git', ['add', '-A'], { cwd: dir });
    execFileSync('git', ['commit', '-qm', 'init'], { cwd: dir });
    const r = spawnSync('node', [bin, 'ship', '--no-fix', '--strict'], { cwd: dir, encoding: 'utf8' });
    check('--strict exits 0 on a genuinely clean repo', r.status === 0, r.stdout);
    check('--strict adds no failure note when it passes', !/--strict: failing/.test(r.stdout));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // --- the invariant: ShipClear never hands out a permanently-green image ---
  check('the report module contains no static badge image',
    !/shields\.io\/badge\/ShipClear/.test(
      fs.readFileSync(path.join(here, '../cli/lib/report.js'), 'utf8')));
  check('a CLEARED markdown report offers the live badge, not a green picture', (() => {
    const md = renderMarkdown({ findings: [], notes: [], verdict: 'CLEARED', version: '0.0.0' });
    return md.includes('shipclear badge') && !/shields\.io\/badge/.test(md);
  })());
  check('a CLEARED terminal report offers the live badge, not a green picture', (() => {
    const out = renderTerminal({ findings: [], notes: [], verdict: 'CLEARED', version: '0.0.0' });
    return out.includes('shipclear badge') && !/shields\.io\/badge/.test(out);
  })());
  // A quick scan skips history and dependencies, so it has not earned any
  // badge claim at all.
  check('a quick scan never mentions the badge', (() => {
    const out = renderTerminal({ findings: [], notes: [], verdict: 'CLEARED', version: '0.0.0', quick: true });
    return !/badge/i.test(out);
  })());
}

console.log(`\n${passed} passed, ${failures.length} failed\n`);
if (failures.length) process.exit(1);
