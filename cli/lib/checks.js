import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  findSecrets, looksPlaceholder, entropy, maskSecret, lineOfIndex,
  realLookingEmails, SSN, PASSWORD_ASSIGNMENT, SUSPICIOUS_ACCOUNT_EMAIL,
  personalPaths, TLS_VERIFICATION_OFF, DEBUG_MODE_ON, isSecretishKey,
} from './patterns.js';
import { loadIgnore } from './ignore.js';
import { runInfraChecks, infraContext, INFRA_RUNNERS } from './infra.js';
import { REGISTRY, QUICK_SKIP_REASON } from './registry.js';
import { walkFiles, isTextCandidate, isSkippedPath, readFileSafe } from './scan.js';
import { isGitRepo, hasCommits, hasRemote, branchNames, trackedFiles, untrackedFiles, historyAddedLines } from './git.js';

const ENV_FILE = /^\.env(?:\..+)?$/;
// Covers .env.example but also .env.local.example, .env.production.sample,
// etc. — real starters (nextjs-subscription-payments) use the nested forms.
const ENV_TEMPLATE = /^\.env(?:\..+)?\.(?:example|sample|template)$|^\.env\.(?:example|sample|template)$/;
const KEY_FILE = /(\.pem|\.p12|\.pfx|\.ppk)$|(^|\/)id_(?:rsa|ed25519|ecdsa|dsa)(\.pub)?$/;
const DATA_FILE_EXT = new Set(['.csv', '.tsv', '.sql', '.jsonl', '.ndjson']);
// .mdc: Cursor rules files — prose instructions, not code.
const DOC_EXT = new Set(['.md', '.mdx', '.mdc', '.rst', '.txt']);
// .claude/skills, commands, agents, and settings.json are intentionally
// shareable project config — only the local/private pieces are artifacts.
const AGENT_ARTIFACTS = ['.claude/settings.local.json', '.codex/', '.aider', '.specstory/'];

const isEnvFile = (rel) => ENV_FILE.test(path.posix.basename(rel)) && !isEnvTemplate(rel);
const isEnvTemplate = (rel) => ENV_TEMPLATE.test(path.posix.basename(rel));
const isKeyFile = (rel) => KEY_FILE.test(rel);
const isDataFile = (rel) => DATA_FILE_EXT.has(path.extname(rel).toLowerCase());
const isDocFile = (rel) => DOC_EXT.has(path.extname(rel).toLowerCase());
// A database password in a compose/k8s file needs an extra rotation step that
// fails silently if missed — see containerDbNote in report.js.
const isContainerConfig = (rel) => /^(?:docker-)?compose(?:[.-].+)?\.ya?ml$|\.ya?ml$/i.test(path.posix.basename(rel));

/**
 * Run the deterministic layer of the gate.
 *
 * Every check lives in REGISTRY (lib/registry.js) and is run through it, so
 * the number of checks is counted rather than claimed, and a check that
 * cannot run here is reported as skipped rather than silently passing. That
 * distinction is the point: "all checks passed" on a project whose
 * dependencies were never looked at is the false all-clear this tool exists
 * to prevent.
 *
 * Returns { findings, notes, inGit, checks }, where checks is one entry per
 * registry item: { id, label, status: 'passed' | 'findings' | 'skipped',
 * count, reason }.
 */
export function runGate(root, { quick = false, onCheck = null } = {}) {
  const c = buildContext(root, quick);

  for (const entry of REGISTRY) {
    let record;
    if (quick && !entry.quick) {
      record = { id: entry.id, label: entry.label, status: 'skipped', count: 0, reason: QUICK_SKIP_REASON };
    } else {
      const skipped = entry.skip ? entry.skip(c) : null;
      if (skipped) {
        record = { id: entry.id, label: entry.label, status: 'skipped', count: 0, ...asSkip(skipped) };
      } else {
        c.pendingSkip = null;
        const found = RUNNERS[entry.id](c);
        for (const f of found) Object.defineProperty(f, '_check', { value: entry.id, enumerable: false });
        c.findings.push(...found);
        record = c.pendingSkip
          ? { id: entry.id, label: entry.label, status: 'skipped', count: 0, ...asSkip(c.pendingSkip) }
          : { id: entry.id, label: entry.label, status: found.length ? 'findings' : 'passed', count: found.length };
      }
    }
    c.checks.push(record);
    if (onCheck) onCheck(record);
  }

  return { findings: c.findings, notes: c.notes, inGit: c.inGit, checks: c.checks };
}

/** A skip is a plain reason, or a reason plus the steps that would turn the check on. */
const asSkip = (s) => (typeof s === 'string'
  ? { reason: s, steps: [], stepsLabel: null }
  : { reason: s.reason, steps: s.steps || [], stepsLabel: s.stepsLabel || null });

/**
 * Everything the checks share: the two file lists, a memoized reader, and the
 * answers to the questions the skip predicates ask.
 */
function buildContext(root, quick) {
  const ignored = loadIgnore(root);
  const inGit = isGitRepo(root);

  // Two lists, deliberately. They answer different questions, and conflating
  // them is how this gate once handed out a false CLEARED.
  //
  // `trackedList` — what git already records. Only this can answer "is a
  //   secrets file *committed*", which is what env-tracked and friends claim.
  // `allFiles` — what a commit would contain: tracked, plus untracked files
  //   git isn't ignoring, i.e. everything `git add -A` would pick up. Content
  //   checks use this, because the realistic beginner order is build →
  //   `ship` → `git add -A && commit && push`: a brand-new server.js holding
  //   a hardcoded key was invisible to every in-code check and the gate said
  //   CLEARED, which that last command then converted into a real leak.
  //
  // Keeping them separate is the whole design: widening one list would have
  // reported an untracked .env as "your .env is checked into git" — a false
  // critical, and the reason this fix needed a decision rather than an edit.
  const trackedList = inGit ? trackedFiles(root).filter((f) => !ignored(f)) : [];
  const untrackedList = inGit
    ? untrackedFiles(root).filter((f) => !ignored(f) && !isSkippedPath(f))
    : [];
  const allFiles = inGit
    ? [...trackedList, ...untrackedList]
    : walkFiles(root).filter((f) => !ignored(f));

  const notes = [];
  if (!inGit) notes.push('Not a git repository — history and tracked-file checks were skipped.');

  // Memoized because the content checks each walk the file list now that they
  // are separate; without it the split would read every file five times.
  const cache = new Map();
  const binaries = new Map();

  return {
    root,
    quick,
    ignored,
    inGit,
    hasCommits: inGit && hasCommits(root),
    trackedList,
    untrackedList,
    uncommitted: new Set(untrackedList),
    allFiles,
    notes,
    findings: [],
    checks: [],
    seenSecretValues: new Set(),
    infra: null,
    pendingSkip: null,
    read(rel) {
      if (!cache.has(rel)) cache.set(rel, readFileSafe(path.join(root, rel)));
      return cache.get(rel);
    },
    has(name) {
      if (!binaries.has(name)) binaries.set(name, hasBinary(name));
      return binaries.get(name);
    },
    /** A check that only discovers at runtime that it cannot run says so. */
    skip(reason) { this.pendingSkip = reason; },
  };
}

/**
 * The files the content checks look at: everything a commit would contain,
 * minus the ones that are supposed to hold secrets.
 */
function* codeFiles(c, { skipDocs = false } = {}) {
  for (const rel of c.allFiles) {
    if (!isTextCandidate(rel) || isEnvFile(rel) || isEnvTemplate(rel) || isKeyFile(rel)) continue;
    // ShipClear's own store for the test logins the prevention rules tell the
    // AI to generate. It is *supposed* to contain credentials, exactly as
    // .env is — finding them there is not a finding. Its dangerous state (a
    // committed registry) is covered by the tracked-state check.
    if (rel.startsWith('.shipclear/')) continue;
    if (skipDocs && isDocFile(rel)) continue;
    const content = c.read(rel);
    if (content === null) continue;
    yield [rel, content];
  }
}


/** One runner per registry entry, keyed by its id. */
const RUNNERS = {
  'secrets-in-code': (c) => {
    const out = [];
    // A generic-secret on the same line as a test-account is the same problem
    // told twice — keep the clearer explanation. This used to be a pass over
    // the findings afterwards, which left this check reporting a count it no
    // longer had: "2 to look at" above a report containing one. The logins
    // check runs first now, so the duplicate is never created.
    const accountLines = new Set(
      c.findings.filter((f) => f.id === 'test-account').map((f) => `${f.file}:${f.line}`)
    );
    for (const [rel, content] of codeFiles(c)) {
    for (const hit of findSecrets(content, { includeGeneric: !isDocFile(rel), docFile: isDocFile(rel) })) {
      c.seenSecretValues.add(hit.match);
      const line = lineOfIndex(content, hit.index);
      if (hit.patternId === 'generic-secret' && accountLines.has(`${rel}:${line}`)) continue;
      out.push({
        id: hit.patternId === 'generic-secret' ? 'generic-secret' : 'secret-in-code',
        severity: hit.severity,
        file: rel,
        line,
        detail: `${hit.name}: \`${maskSecret(hit.value ?? hit.match)}\``,
        uncommitted: c.uncommitted.has(rel),
        dbInContainer: isContainerConfig(rel) && /volumes\s*:/.test(content)
          && /postgres|mysql|mariadb|mongo|redis/i.test(hit.name + hit.match),
      });
    }
    }
    return out;
  },

  'hardcoded-logins': (c) => {
    const out = [];
    for (const [rel, content] of codeFiles(c, { skipDocs: true })) {
    // Hardcoded account pairs: a suspicious email literal with a password
    // assignment within three lines of it.
    const lines = content.split('\n');
    lines.forEach((lineText, i) => {
      if (!SUSPICIOUS_ACCOUNT_EMAIL.test(lineText)) return;
      const nearby = lines.slice(Math.max(0, i - 3), i + 4).join('\n');
      if (PASSWORD_ASSIGNMENT.test(nearby)) {
        out.push({
          id: 'test-account',
          severity: 'high',
          file: rel,
          line: i + 1,
          uncommitted: c.uncommitted.has(rel),
          detail: 'A login (username or email) and password pair is written directly in the code.',
        });
      }
    });
    }
    return out;
  },

  'tls-verification-off': (c) => {
    const out = [];
    for (const [rel, content] of codeFiles(c, { skipDocs: true })) {
    TLS_VERIFICATION_OFF.lastIndex = 0;
    let tls;
    while ((tls = TLS_VERIFICATION_OFF.exec(content))) {
      out.push({
        id: 'tls-verification-off',
        severity: 'medium',
        file: rel,
        line: lineOfIndex(content, tls.index),
        detail: `\`${tls[0].trim()}\``,
      });
    }
    }
    return out;
  },

  'debug-mode-on': (c) => {
    const out = [];
    for (const [rel, content] of codeFiles(c, { skipDocs: true })) {
    DEBUG_MODE_ON.lastIndex = 0;
    let dbg;
    while ((dbg = DEBUG_MODE_ON.exec(content))) {
      out.push({
        id: 'debug-mode-on',
        severity: 'medium',
        file: rel,
        line: lineOfIndex(content, dbg.index),
        detail: `\`${dbg[0].trim()}\``,
      });
    }
    }
    return out;
  },

  'personal-paths': (c) => {
    const out = [];
    for (const [rel, content] of codeFiles(c, { skipDocs: true })) {
    // One finding per file, not per occurrence. This rule matches a string
    // that recurs — a path baked into a lockfile or a generated bundle can
    // appear thousands of times in one file, and emitting each hit once
    // turned a single real run into 33,569 findings and a 14.5 MB report,
    // because every one of them repeats the full remediation prose. The
    // actionable unit is the file, so report the file and count the rest.
    const pathHits = personalPaths(content);
    if (pathHits.length) {
      const unique = [...new Set(pathHits.map((h) => h.match))];
      const shown = unique.slice(0, 3).map((u) => `\`${u}\``).join(', ');
      const more = unique.length > 3 ? `, and ${unique.length - 3} more` : '';
      out.push({
        id: 'personal-path',
        severity: 'low',
        file: rel,
        line: lineOfIndex(content, pathHits[0].index),
        detail: shown + more
          + (pathHits.length > unique.length ? ` (${pathHits.length} occurrences)` : ''),
      });
    }
    }
    return out;
  },

  'committed-env-files': (c) => {
    const out = [];
    for (const rel of c.trackedList) {
      if (isEnvFile(rel)) out.push({ id: 'env-tracked', severity: 'critical', file: rel });
    }
    return out;
  },

  'committed-key-files': (c) => {
    const out = [];
    for (const rel of c.trackedList) {
      if (!isEnvFile(rel) && isKeyFile(rel)) out.push({ id: 'key-file-tracked', severity: 'critical', file: rel });
    }
    return out;
  },

  'committed-test-logins': (c) => {
    const out = [];
    for (const rel of c.trackedList) {
      // The prevention rules tell the AI to keep generated test credentials
      // here, git-ignored. If it's tracked, that ignore never happened.
      if (!isEnvFile(rel) && !isKeyFile(rel) && rel.startsWith('.shipclear/')) {
        out.push({
          id: 'test-account',
          severity: 'high',
          file: rel,
          detail: 'This is where ShipClear\'s rules tell your AI to keep test logins — it must never be committed.',
        });
      }
    }
    return out;
  },

  'agent-artifacts': (c) => {
    const out = [];
    for (const rel of c.trackedList) {
      if (isEnvFile(rel) || isKeyFile(rel) || rel.startsWith('.shipclear/')) continue;
      const artifact = AGENT_ARTIFACTS.find((p) => rel.startsWith(p));
      if (artifact) out.push({ id: 'agent-artifact', severity: 'low', file: rel });
    }
    return out;
  },

  'uncommitted-key-files': (c) => {
    const out = [];
  // --- not committed yet, but `git add -A` would take it ---
  // A private key sitting in the project folder has leaked nothing, so this
  // is not a critical — but it is one command away from being one, and the
  // .gitignore line that prevents it costs nothing.
  for (const rel of c.untrackedList) {
    if (isKeyFile(rel)) out.push({ id: 'key-file-uncommitted', severity: 'high', file: rel });
  }
    return out;
  },

  'gitignore-coverage': (c) => {
    const out = [];
  // --- .gitignore hygiene ---
  const gitignorePath = path.join(c.root, '.gitignore');
  const gitignore = fs.existsSync(gitignorePath) ? fs.readFileSync(gitignorePath, 'utf8') : null;
  const coversEnv =
    gitignore && gitignore.split('\n').some((l) => /^(\.env(\.\*)?|\*\.env|\.env\*)\s*$/.test(l.trim()));
  if (!coversEnv) {
    out.push({
      id: 'gitignore-incomplete',
      severity: 'high',
      file: '.gitignore',
      detail: gitignore === null ? 'No .gitignore file exists.' : '`.env` is not ignored.',
    });
  }

    return out;
  },

  'env-example-leak': (c) => {
    const out = [];
  // --- .env.example should contain shapes, not values ---
  for (const rel of c.allFiles.filter(isEnvTemplate)) {
    const content = c.read(rel);
    if (content === null) continue;
    content.split('\n').forEach((lineText, i) => {
      const m = lineText.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^"'\n#]*)/);
      if (!m) return;
      const value = m[2].trim();
      if (!value || looksPlaceholder(value)) return;
      const specific = findSecrets(value, { includeGeneric: false }).length > 0;
      // Entropy alone cannot tell a secret from any other dense string, so it
      // only gets a vote when the *name* claims a credential. Without this the
      // check reported `SEED_SUPERADMIN_EMAIL=someone@gmail.com`,
      // `RP_ID=app.example.com`, `DB_PATH=/home/you/app/data.db` and
      // `TERMINAL_IMAGE=nikolaik/python-nodejs:python3.11` as leaked secrets —
      // four HIGH findings in one real run, none of them a credential.
      // A specific pattern match (a live `sk-ant-…`, an AWS key) still stands
      // on its own, whatever the variable is called.
      if (!specific && !isSecretishKey(m[1])) return;
      // Values the specific patterns already cleared don't get a second
      // chance via entropy: scheme:// URLs (a connection string with a real
      // password would have matched; without one it's a template) and JWTs
      // (only service-role JWTs are secrets — anon keys are public by design).
      if (!specific && /^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return;
      if (!specific && /^eyJ[A-Za-z0-9_-]+\./.test(value)) return;
      if (specific || (value.length >= 12 && entropy(value) > 3.5)) {
        c.seenSecretValues.add(value);
        out.push({
          id: 'env-example-leak',
          severity: 'high',
          file: rel,
          line: i + 1,
          uncommitted: c.uncommitted.has(rel),
          detail: `\`${m[1]}\` has a real-looking value (\`${maskSecret(value)}\`).`,
        });
      }
    });
  }
    return out;
  },

  'pii-data-files': (c) => {
    const out = [];
  // --- real-looking personal data in tracked data files ---
  for (const rel of c.allFiles.filter(isDataFile)) {
    const content = c.read(rel);
    if (content === null) continue;
    const emails = realLookingEmails(content);
    SSN.lastIndex = 0;
    const ssns = content.match(SSN) || [];
    if (emails.length >= 3 || ssns.length > 0) {
      const parts = [];
      if (emails.length >= 3) parts.push(`${emails.length} distinct email addresses`);
      if (ssns.length > 0) parts.push(`${ssns.length} SSN-shaped values`);
      out.push({
        id: 'pii-data-file', severity: 'high', file: rel,
        uncommitted: c.uncommitted.has(rel), detail: parts.join(' and '),
      });
    }
  }
    return out;
  },

  'secrets-in-history': (c) => {
    const out = [];
  // --- secrets anywhere in git history, even if since deleted ---
  if (c.inGit && hasCommits(c.root)) {
    const remoteExists = hasRemote(c.root);
    const currentBranch = branchNames(c.root)[0] || 'main';
    const seen = new Set();
    // One finding per file+commit, not per secret: two keys leaked in the
    // same .env in the same commit are one problem with one fix, and two
    // identical ten-line paragraphs read as "do this twice" to a beginner.
    const byLocation = new Map();
    for (const { commit, file, text } of historyAddedLines(c.root)) {
      if (c.ignored(file)) continue;
      for (const hit of findSecrets(text, { includeGeneric: false, docFile: isDocFile(file) })) {
        if (seen.has(hit.match)) continue;
        seen.add(hit.match);
        // Already reported from the working tree — that finding's advice
        // covers rotation, so a history duplicate is just noise. History
        // findings are for secrets that were *deleted* but still leak.
        if (c.seenSecretValues.has(hit.match)) continue;
        const key = `${file}@${commit}`;
        const label = `${hit.name} (\`${maskSecret(hit.match)}\`)`;
        const existing = byLocation.get(key);
        if (existing) {
          existing.names.push(label);
          existing.detail = `${existing.names.join(' and ')} first added in commit ${commit}.`;
          continue;
        }
        const finding = {
          id: 'secret-in-history',
          severity: 'critical',
          file,
          commit,
          hasRemote: remoteExists,
          branch: currentBranch,
          names: [label],
          detail: `${label} first added in commit ${commit}.`,
        };
        byLocation.set(key, finding);
        out.push(finding);
      }
    }
  }
    return out;
  },

  'test-registry-present': (c) => {
    const out = [];
  // --- generated test logins exist; the rules promise a launch-time reminder ---
  if (fs.existsSync(path.join(c.root, '.shipclear', 'test-accounts.json'))) {
    out.push({
      id: 'test-registry-present',
      severity: 'info',
      file: '.shipclear/test-accounts.json',
      // Untracked but not ignored: nothing has leaked, but `git add -A` would
      // commit these logins. Said here rather than as its own finding — the
      // registry existing is the normal, intended state and must not move the
      // verdict.
      detail: c.uncommitted.has('.shipclear/test-accounts.json')
        ? 'Also worth one line of housekeeping: git is not ignoring this file, so a `git add -A` would commit it. Add `.shipclear/` to your .gitignore (or run `shipclear setup`, which does it for you).'
        : undefined,
    });
  }
    return out;
  },

  'env-example-missing': (c) => {
    const out = [];
  // --- .env exists but no template for teammates ---
  if (fs.existsSync(path.join(c.root, '.env')) && !allFilesHasTemplate(c.root, c.allFiles)) {
    out.push({ id: 'env-example-missing', severity: 'info', file: '.env.example' });
  }
    return out;
  },

  // When gitleaks is installed it runs as a second opinion on top of the
  // built-in patterns; anything it finds that we didn't becomes an extra
  // secret-in-code finding. Its skip reason says it is optional.
  'deep-secret-scan': (c) => {
    const out = [];
    runGitleaks(c, out);
    return out;
  },

  'dependency-vulns': (c) => {
    const out = [];
    // osv-scanner covers every ecosystem, so it takes precedence over the
    // npm-only audit path when it is installed.
    if (c.has('osv-scanner') && runOsvScanner(c.root, out, c.notes)) return out;
    if (!fs.existsSync(path.join(c.root, 'package-lock.json'))) {
      c.skip('osv-scanner is installed but could not run, and there is no package-lock.json to fall back on');
      return out;
    }
    try {
      let auditJson;
      try {
        auditJson = execFileSync('npm', ['audit', '--json'], {
          cwd: c.root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 60000,
        });
      } catch (err) {
        // npm audit exits non-zero when vulnerabilities exist; the JSON is
        // still on stdout.
        auditJson = err.stdout;
      }
      const meta = JSON.parse(auditJson)?.metadata?.vulnerabilities || {};
      const serious = (meta.high || 0) + (meta.critical || 0);
      if (serious > 0) {
        out.push({
          id: 'dependency-vulns',
          severity: 'high',
          file: 'package-lock.json',
          detail: `${serious} high/critical known ${serious === 1 ? 'vulnerability' : 'vulnerabilities'} (npm audit).`,
        });
      }
    } catch {
      c.skip('`npm audit` could not run — you are offline, or npm is unavailable');
    }
    return out;
  },
};

// The deployment checks live in infra.js; each is wired in by its id so it
// reports its own status like every other check.
for (const id of Object.keys(INFRA_RUNNERS)) {
  RUNNERS[id] = (c) => {
    if (!c.infra) c.infra = infraContext(c.root, { ignored: c.ignored });
    return INFRA_RUNNERS[id](c.infra);
  };
}

function allFilesHasTemplate(root, files) {
  return files.some(isEnvTemplate) || fs.existsSync(path.join(root, '.env.example'));
}

function hasBinary(name) {
  try {
    execFileSync(process.platform === 'win32' ? 'where' : 'which', [name], {
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    return true;
  } catch {
    return false;
  }
}

const GITLEAKS_UNUSABLE =
  'gitleaks is installed but could not be run here, so its deeper pass never happened — '
  + "ShipClear's own secret scan ran either way";

// When gitleaks is installed, run it as a second opinion on top of the
// built-in patterns — its rule set is deeper than ours. Everything it finds
// that we didn't becomes an additional secret-in-code finding, pushed into
// `out` so the check reports its own count like every other runner.
//
// Takes the context rather than its five pieces. It used to take
// (root, findings, notes, ignored) while the call site passed five
// arguments, so `notes` was the findings array and `ignored` was the notes
// array: the "gitleaks also ran" note was pushed into the findings, where
// runGate's Object.defineProperty crashed on a string, and the first real
// leak called an array as a function and was swallowed by the catch below.
// Two arrays and a function as positional parameters is what made that
// invisible, so there are no longer five of them.
function runGitleaks(c, out) {
  const { root, ignored } = c;
  const reportPath = path.join(os.tmpdir(), `shipclear-gitleaks-${process.pid}.json`);
  const attempts = [
    ['dir', root, '--no-banner', '--exit-code', '0', '--report-format', 'json', '--report-path', reportPath],
    ['detect', '--source', root, '--no-git', '--no-banner', '--exit-code', '0', '--report-format', 'json', '--report-path', reportPath],
  ];
  try {
    let ran = false;
    for (const args of attempts) {
      try {
        execFileSync('gitleaks', args, { cwd: root, stdio: ['ignore', 'ignore', 'ignore'], timeout: 120000 });
        ran = true;
        break;
      } catch (err) {
        // Older/newer CLI syntax mismatch → try the next form. A written
        // report despite non-zero exit also counts as a successful run.
        if (fs.existsSync(reportPath)) { ran = true; break; }
      }
    }
    if (!ran) { c.skip(GITLEAKS_UNUSABLE); return; }
    const leaks = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    const already = new Set(c.findings.map((f) => `${f.file}:${f.line || ''}`));
    let added = 0;
    for (const leak of leaks) {
      const rel = path.relative(root, path.isAbsolute(leak.File) ? leak.File : path.join(root, leak.File))
        .split(path.sep).join('/');
      if (ignored(rel) || already.has(`${rel}:${leak.StartLine}`)) continue;
      out.push({
        id: 'secret-in-code',
        severity: 'critical',
        file: rel,
        line: leak.StartLine,
        detail: `${leak.RuleID} (found by gitleaks)`,
      });
      added++;
    }
    c.notes.push(`gitleaks also ran (${added === 0 ? 'no additional findings' : `${added} additional finding${added === 1 ? '' : 's'}`}).`);
  } catch {
    // gitleaks present but unusable. The built-in scan already ran, but this
    // check did not — reporting it as passed is the false all-clear this
    // gate exists to prevent, so it is skipped instead.
    out.length = 0;
    c.skip(GITLEAKS_UNUSABLE);
  } finally {
    fs.rmSync(reportPath, { force: true });
  }
}

// When osv-scanner is installed it covers every ecosystem (Python, Go, Rust,
// …), so it takes precedence over the npm-only audit path.
function runOsvScanner(root, findings, notes) {
  try {
    let out;
    try {
      out = execFileSync('osv-scanner', ['--format', 'json', '-r', root], {
        cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 120000,
      });
    } catch (err) {
      out = err.stdout; // non-zero exit when vulnerabilities exist
    }
    const results = JSON.parse(out)?.results || [];
    let vulns = 0;
    for (const r of results) for (const p of r.packages || []) vulns += (p.vulnerabilities || []).length;
    if (vulns > 0) {
      findings.push({
        id: 'dependency-vulns',
        severity: 'high',
        detail: `${vulns} known ${vulns === 1 ? 'vulnerability' : 'vulnerabilities'} across your dependencies (osv-scanner).`,
      });
    }
    notes.push('Dependency check ran via osv-scanner (covers all ecosystems).');
    return true;
  } catch {
    return false;
  }
}
