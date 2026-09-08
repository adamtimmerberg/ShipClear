import fs from 'node:fs';
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
const ENV_TEMPLATE = /^\.env\.(?:example|sample|template)$/;
const KEY_FILE = /(\.pem|\.p12|\.pfx|\.ppk)$|(^|\/)id_(?:rsa|ed25519|ecdsa|dsa)(\.pub)?$/;
const DATA_FILE_EXT = new Set(['.csv', '.tsv', '.sql', '.jsonl', '.ndjson']);
const DOC_EXT = new Set(['.md', '.mdx', '.rst', '.txt']);
const AGENT_ARTIFACTS = ['.claude/', '.codex/', '.aider', '.specstory/'];

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

  // --- secrets in code (skipping .env files, which are *supposed* to hold them) ---
  for (const rel of allFiles) {
    if (!isTextCandidate(rel) || isEnvFile(rel) || isEnvTemplate(rel) || isKeyFile(rel)) continue;
    const content = read(rel);
    if (content === null) continue;

    for (const hit of findSecrets(content, { includeGeneric: !isDocFile(rel) })) {
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
      if (specific || (value.length >= 12 && entropy(value) > 3.5)) {
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
        // Still present in the working tree → already reported as
        // secret-in-code/env-tracked; history adds the rotation warning.
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

  // --- known-vulnerable dependencies (best effort, npm projects only) ---
  if (fs.existsSync(path.join(root, 'package-lock.json'))) {
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
