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
  check('has-remote case says how to install filter-repo', /pip install git-filter-repo/.test(hasRemoteWithFile));
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
  check('has-remote: after a BFG cleanup, tells the user to reset their own folder to the cleaned remote',
    /git fetch && git reset --hard origin\/master/.test(hasRemoteMaster));
  check('has-remote: says to re-run ship to confirm', /Then run `shipclear ship` again/.test(hasRemoteMaster));
  check('has-remote: warns what a BFG failure looks like', /Caused by:/.test(hasRemoteMaster));
  check('has-remote: notes GitHub may keep the old commit reachable for a while', /reachable by its ID/.test(hasRemoteMaster));
  check('has-remote: the AI hand-off sentence matches the file type',
    /scrub that value.*keep the file/.test(hasRemoteWithFile) && /remove that file from every commit/.test(hasRemoteEnv));
  check('has-remote case covers re-adding the remote and the force-push',
    /git remote add origin/.test(hasRemoteWithFile) && /git push --force/.test(hasRemoteWithFile));
  check('has-remote case offers a paste-able ask for the AI assistant', /paste it this sentence/.test(hasRemoteWithFile));
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
  check('quick scan never offers the ship-worthy badge', !quick.includes('add the badge'));
  check('full gate on a real CLEARED verdict does offer the badge', full.includes('add the badge'));
  // Round 4: "scan said Nice, ship said CRITICAL thirty seconds later" —
  // the quick verdict must say what it doesn't look at, not just that it's partial.
  check('quick scan CLEARED says what it skipped', /current files only, not git history/.test(quick));
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
  check('quoted admin email still matches', SUSPICIOUS_ACCOUNT_EMAIL.test(`"email": "${adminEmail}"`));

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

console.log(`\n${passed} passed, ${failures.length} failed\n`);
if (failures.length) process.exit(1);
