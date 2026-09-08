import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  findSecrets, looksPlaceholder, entropy, maskSecret, lineOfIndex,
  realLookingEmails, SSN, PASSWORD_ASSIGNMENT, SUSPICIOUS_ACCOUNT_EMAIL,
  personalPaths,
} from './patterns.js';
import { loadIgnore } from './ignore.js';
import { walkFiles, isTextCandidate, readFileSafe } from './scan.js';
import { isGitRepo, hasCommits, trackedFiles, historyAddedLines } from './git.js';

const ENV_FILE = /^\.env(?:\..+)?$/;
// Covers .env.example but also .env.local.example, .env.production.sample,
// etc. — real starters (nextjs-subscription-payments) use the nested forms.
const ENV_TEMPLATE = /^\.env(?:\..+)?\.(?:example|sample|template)$|^\.env\.(?:example|sample|template)$/;
const KEY_FILE = /(\.pem|\.p12|\.pfx|\.ppk)$|(^|\/)id_(?:rsa|ed25519|ecdsa|dsa)(\.pub)?$/;
const DATA_FILE_EXT = new Set(['.csv', '.tsv', '.sql', '.jsonl', '.ndjson']);
const DOC_EXT = new Set(['.md', '.mdx', '.rst', '.txt']);
// .claude/skills, commands, agents, and settings.json are intentionally
// shareable project config — only the local/private pieces are artifacts.
const AGENT_ARTIFACTS = ['.claude/settings.local.json', '.codex/', '.aider', '.specstory/'];

const isEnvFile = (rel) => ENV_FILE.test(path.posix.basename(rel)) && !isEnvTemplate(rel);
const isEnvTemplate = (rel) => ENV_TEMPLATE.test(path.posix.basename(rel));
const isKeyFile = (rel) => KEY_FILE.test(rel);
const isDataFile = (rel) => DATA_FILE_EXT.has(path.extname(rel).toLowerCase());
const isDocFile = (rel) => DOC_EXT.has(path.extname(rel).toLowerCase());

/**
 * Run the deterministic layer of the gate. Returns { findings, notes, inGit }.
 * Findings: { id, severity, file?, line?, detail?, commit? }.
 * Severity: critical | high | medium | low | info.
 */
export function runGate(root, { quick = false } = {}) {
  const findings = [];
  const notes = [];
  const ignored = loadIgnore(root);
  const inGit = isGitRepo(root);

  const allFiles = (inGit ? trackedFiles(root) : walkFiles(root)).filter((f) => !ignored(f));
  if (!inGit) notes.push('Not a git repository — history and tracked-file checks were skipped.');

  const read = (rel) => readFileSafe(path.join(root, rel));

  // Raw values already reported from the working tree — used to suppress
  // duplicate history findings for secrets that are still present (the
  // in-code finding's fix advice already covers rotation).
  const seenSecretValues = new Set();

  // --- secrets in code (skipping .env files, which are *supposed* to hold them) ---
  for (const rel of allFiles) {
    if (!isTextCandidate(rel) || isEnvFile(rel) || isEnvTemplate(rel) || isKeyFile(rel)) continue;
    const content = read(rel);
    if (content === null) continue;

    for (const hit of findSecrets(content, { includeGeneric: !isDocFile(rel) })) {
      seenSecretValues.add(hit.match);
      findings.push({
        id: hit.patternId === 'generic-secret' ? 'generic-secret' : 'secret-in-code',
        severity: hit.severity,
        file: rel,
        line: lineOfIndex(content, hit.index),
        detail: `${hit.name}: \`${maskSecret(hit.value ?? hit.match)}\``,
      });
    }

    if (!quick && !isDocFile(rel)) {
      // Hardcoded account pairs: a suspicious email literal with a password
      // assignment within three lines of it.
      const lines = content.split('\n');
      lines.forEach((lineText, i) => {
        if (!SUSPICIOUS_ACCOUNT_EMAIL.test(lineText)) return;
        const nearby = lines.slice(Math.max(0, i - 3), i + 4).join('\n');
        if (PASSWORD_ASSIGNMENT.test(nearby)) {
          findings.push({
            id: 'test-account',
            severity: 'high',
            file: rel,
            line: i + 1,
            detail: 'An email + password pair is written directly in the code.',
          });
        }
      });

      for (const hit of personalPaths(content)) {
        findings.push({
          id: 'personal-path',
          severity: 'low',
          file: rel,
          line: lineOfIndex(content, hit.index),
          detail: `\`${hit.match}\``,
        });
      }
    }
  }

  // A generic-secret on the same line as a test-account is the same problem
  // told twice — keep the clearer explanation.
  const accountLines = new Set(
    findings.filter((f) => f.id === 'test-account').map((f) => `${f.file}:${f.line}`)
  );
  const deduped = findings.filter(
    (f) => !(f.id === 'generic-secret' && accountLines.has(`${f.file}:${f.line}`))
  );
  findings.length = 0;
  findings.push(...deduped);

  // --- tracked files that should never be tracked ---
  if (inGit) {
    for (const rel of allFiles) {
      if (isEnvFile(rel)) {
        findings.push({ id: 'env-tracked', severity: 'critical', file: rel });
      } else if (isKeyFile(rel)) {
        findings.push({ id: 'key-file-tracked', severity: 'critical', file: rel });
      } else {
        const artifact = AGENT_ARTIFACTS.find((p) => rel.startsWith(p));
        if (artifact) findings.push({ id: 'agent-artifact', severity: 'low', file: rel });
      }
    }
  }

  // --- .gitignore hygiene ---
  const gitignorePath = path.join(root, '.gitignore');
  const gitignore = fs.existsSync(gitignorePath) ? fs.readFileSync(gitignorePath, 'utf8') : null;
  const coversEnv =
    gitignore && gitignore.split('\n').some((l) => /^(\.env(\.\*)?|\*\.env|\.env\*)\s*$/.test(l.trim()));
  if (!coversEnv) {
    findings.push({
      id: 'gitignore-incomplete',
      severity: 'high',
      file: '.gitignore',
      detail: gitignore === null ? 'No .gitignore file exists.' : '`.env` is not ignored.',
    });
  }

  if (quick) return { findings, notes, inGit };

  // --- .env.example should contain shapes, not values ---
  for (const rel of allFiles.filter(isEnvTemplate)) {
    const content = read(rel);
    if (content === null) continue;
    content.split('\n').forEach((lineText, i) => {
      const m = lineText.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^"'\n#]*)/);
      if (!m) return;
      const value = m[2].trim();
      if (!value || looksPlaceholder(value)) return;
      const specific = findSecrets(value, { includeGeneric: false }).length > 0;
      // Values the specific patterns already cleared don't get a second
      // chance via entropy: scheme:// URLs (a connection string with a real
      // password would have matched; without one it's a template) and JWTs
      // (only service-role JWTs are secrets — anon keys are public by design).
      if (!specific && /^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return;
      if (!specific && /^eyJ[A-Za-z0-9_-]+\./.test(value)) return;
      if (specific || (value.length >= 12 && entropy(value) > 3.5)) {
        seenSecretValues.add(value);
        findings.push({
          id: 'env-example-leak',
          severity: 'high',
          file: rel,
          line: i + 1,
          detail: `\`${m[1]}\` has a real-looking value (\`${maskSecret(value)}\`).`,
        });
      }
    });
  }

  // --- real-looking personal data in tracked data files ---
  for (const rel of allFiles.filter(isDataFile)) {
    const content = read(rel);
    if (content === null) continue;
    const emails = realLookingEmails(content);
    SSN.lastIndex = 0;
    const ssns = content.match(SSN) || [];
    if (emails.length >= 3 || ssns.length > 0) {
      const parts = [];
      if (emails.length >= 3) parts.push(`${emails.length} distinct email addresses`);
      if (ssns.length > 0) parts.push(`${ssns.length} SSN-shaped values`);
      findings.push({ id: 'pii-data-file', severity: 'high', file: rel, detail: parts.join(' and ') });
    }
  }

  // --- secrets anywhere in git history, even if since deleted ---
  if (inGit && hasCommits(root)) {
    const seen = new Set();
    for (const { commit, file, text } of historyAddedLines(root)) {
      if (ignored(file)) continue;
      for (const hit of findSecrets(text, { includeGeneric: false })) {
        if (seen.has(hit.match)) continue;
        seen.add(hit.match);
        // Already reported from the working tree — that finding's advice
        // covers rotation, so a history duplicate is just noise. History
        // findings are for secrets that were *deleted* but still leak.
        if (seenSecretValues.has(hit.match)) continue;
        findings.push({
          id: 'secret-in-history',
          severity: 'critical',
          file,
          commit,
          detail: `${hit.name} (\`${maskSecret(hit.match)}\`) first added in commit ${commit}.`,
        });
      }
    }
  }

  // --- .env exists but no template for teammates ---
  if (fs.existsSync(path.join(root, '.env')) && !allFilesHasTemplate(root, allFiles)) {
    findings.push({ id: 'env-example-missing', severity: 'info', file: '.env.example' });
  }

  // --- optional deeper scanners, used automatically when installed ---
  if (hasBinary('gitleaks')) runGitleaks(root, findings, notes, ignored);
  const osvRan = hasBinary('osv-scanner') && runOsvScanner(root, findings, notes);

  // --- known-vulnerable dependencies (best effort, npm projects only) ---
  if (osvRan) {
    // covered above, across all ecosystems
  } else if (fs.existsSync(path.join(root, 'package-lock.json'))) {
    try {
      let auditJson;
      try {
        auditJson = execFileSync('npm', ['audit', '--json'], {
          cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 60000,
        });
      } catch (err) {
        // npm audit exits non-zero when vulnerabilities exist; the JSON is
        // still on stdout.
        auditJson = err.stdout;
      }
      const meta = JSON.parse(auditJson)?.metadata?.vulnerabilities || {};
      const serious = (meta.high || 0) + (meta.critical || 0);
      if (serious > 0) {
        findings.push({
          id: 'dependency-vulns',
          severity: 'high',
          file: 'package-lock.json',
          detail: `${serious} high/critical known ${serious === 1 ? 'vulnerability' : 'vulnerabilities'} (npm audit).`,
        });
      }
    } catch {
      notes.push('Could not run `npm audit` (offline or npm unavailable) — dependency check skipped.');
    }
  } else if (fs.existsSync(path.join(root, 'package.json'))) {
    notes.push('No package-lock.json — dependency vulnerability check skipped.');
  }

  return { findings, notes, inGit };
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

// When gitleaks is installed, run it as a second opinion on top of the
// built-in patterns — its rule set is deeper than ours. Everything it finds
// that we didn't becomes an additional secret-in-code finding.
function runGitleaks(root, findings, notes, ignored) {
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
    if (!ran) return;
    const leaks = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    const already = new Set(findings.map((f) => `${f.file}:${f.line || ''}`));
    let added = 0;
    for (const leak of leaks) {
      const rel = path.relative(root, path.isAbsolute(leak.File) ? leak.File : path.join(root, leak.File))
        .split(path.sep).join('/');
      if (ignored(rel) || already.has(`${rel}:${leak.StartLine}`)) continue;
      findings.push({
        id: 'secret-in-code',
        severity: 'critical',
        file: rel,
        line: leak.StartLine,
        detail: `${leak.RuleID} (found by gitleaks)`,
      });
      added++;
    }
    notes.push(`gitleaks also ran (${added === 0 ? 'no additional findings' : `${added} additional finding${added === 1 ? '' : 's'}`}).`);
  } catch {
    // gitleaks present but unusable — the built-in scan already ran.
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
