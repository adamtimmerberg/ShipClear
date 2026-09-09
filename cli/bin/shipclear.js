#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runGate } from '../lib/checks.js';
import { applyFixes, resetHistory, installHook, envExampleFrom, GITIGNORE_BLOCK } from '../lib/fix.js';
import { renderTerminal, renderMarkdown, verdictOf, VERDICT_TEXT } from '../lib/report.js';
import { findSecrets, maskSecret, lineOfIndex } from '../lib/patterns.js';
import { isGitRepo, stagedFiles, stagedContent } from '../lib/git.js';
import { loadIgnore } from '../lib/ignore.js';

const pkg = JSON.parse(
  fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../package.json'), 'utf8')
);

const HELP = `
ShipClear v${pkg.version} — the last command before you launch.

Usage:
  shipclear setup          Prepare this project: .env files, .gitignore, commit guard
  shipclear scan           Quick scan for secrets in this project
  shipclear scan --staged  Scan only what's about to be committed (used by the guard)
  shipclear ship           Full safe-to-ship gate → SHIP-REPORT.md + verdict
  shipclear ship --no-fix  Same, but don't apply automatic fixes
  shipclear ship --fix-history
                           Also erase git history to remove a leaked secret from
                           old commits (only when nothing was ever pushed; refuses
                           if it would lose branches or stashes)

Everything runs locally. Nothing is uploaded, ever.
Docs: https://github.com/adamtimmerberg/ShipClear
`;

function cmdSetup(root) {
  const done = [];
  const warnings = [];
  const gitignorePath = path.join(root, '.gitignore');
  const gitignore = fs.existsSync(gitignorePath) ? fs.readFileSync(gitignorePath, 'utf8') : '';
  if (!gitignore.split('\n').some((l) => /^(\.env(\.\*)?|\*\.env|\.env\*)\s*$/.test(l.trim()))) {
    fs.writeFileSync(gitignorePath, gitignore + GITIGNORE_BLOCK);
    done.push('.gitignore now excludes .env files and the ShipClear report — this protects future commits; if a secret was already committed earlier, `shipclear ship` will find it');
  }
  const envPath = path.join(root, '.env');
  if (!fs.existsSync(envPath)) {
    fs.writeFileSync(envPath, '# Real values live here. This file is git-ignored — never commit it.\n');
    done.push('created .env (for real values — stays on your machine)');
  }
  if (!fs.existsSync(path.join(root, '.env.example'))) {
    // Same derivation the auto-fix uses: variable names from .env, values stripped.
    const example = envExampleFrom(envPath);
    fs.writeFileSync(path.join(root, '.env.example'), example);
    done.push(example.includes('=')
      ? 'created .env.example (your variable names, no values — safe to share)'
      : 'created .env.example (a safe-to-share template — add a line per setting as you add them to .env)');
  }
  const inGit = isGitRepo(root);
  if (inGit) {
    if (installHook(root)) {
      done.push('installed the commit guard (secrets can no longer be committed)');
    } else {
      warnings.push('this project already has a pre-commit hook, so ShipClear left it alone — your commits are NOT yet protected. Add `shipclear scan --staged` as a line in that existing hook to turn protection on.');
    }
  } else {
    warnings.push("this folder isn't set up with git yet, so ShipClear couldn't install the commit guard — the safety net that stops a secret from ever being committed. Run `git init` in this folder, then run `shipclear setup` again.");
  }

  console.log(warnings.length ? '\n  ShipClear setup finished — but read this first:' : '\n  ShipClear setup complete.');
  for (const d of done) console.log(`   ✔ ${d}`);
  if (!done.length && !warnings.length) console.log('   ✔ everything was already in place');
  for (const w of warnings) console.log(`   ⚠ ${w}`);
  // The files above sit uncommitted otherwise, and "commit" is not an
  // instruction to someone who has never run git — give the command.
  if (inGit && done.length) console.log('\n  These changes aren\'t saved into git yet — run: git add -A && git commit -m "add ShipClear protection"');
  console.log('\n  Before you launch or go public: shipclear ship\n');
}

function cmdScanStaged(root, quiet) {
  if (!isGitRepo(root)) {
    console.error('Not a git repository.');
    return 0;
  }
  const ignored = loadIgnore(root);
  const blockers = [];
  for (const rel of stagedFiles(root)) {
    if (ignored(rel)) continue;
    if (/^\.env(\..+)?$/.test(path.posix.basename(rel)) && !/\.(example|sample|template)$/.test(rel)) {
      blockers.push({ rel, reason: 'this is a .env secrets file — it must never be committed' });
      continue;
    }
    const content = stagedContent(root, rel);
    if (content === null) continue;
    for (const hit of findSecrets(content, { includeGeneric: false })) {
      blockers.push({
        rel: `${rel}:${lineOfIndex(content, hit.index)}`,
        reason: `${hit.name} (\`${maskSecret(hit.match)}\`)`,
      });
    }
  }
  if (blockers.length === 0) {
    if (!quiet) console.log('ShipClear: staged changes are clean.');
    return 0;
  }
  console.error('\n🛑 ShipClear blocked this commit — it contains secrets:\n');
  for (const b of blockers) console.error(`   • ${b.rel} — ${b.reason}`);
  console.error('\nMove secrets to .env, restage, and commit again.');
  console.error('(If this is a confirmed false positive, add the path to .shipclearignore.)\n');
  return 1;
}

function cmdScan(root) {
  const { findings, notes } = runGate(root, { quick: true });
  const verdict = verdictOf(findings);
  console.log(renderTerminal({ findings, notes, verdict, version: pkg.version, quick: true }));
  return findings.some((f) => f.severity === 'critical') ? 1 : 0;
}

function cmdShip(root, { fix = true, fixHistory = false } = {}) {
  let { findings, notes } = runGate(root);
  const fixes = fix ? applyFixes(root, findings) : [];

  if (fixHistory) {
    const { done, refused } = resetHistory(root, findings);
    if (done) {
      fixes.push(done);
      // History is gone — re-run the gate so the verdict reflects the
      // repo as it now is, not as it was before the reset.
      ({ findings, notes } = runGate(root));
    } else {
      notes.push(`--fix-history was not applied: ${refused}`);
    }
  }

  const verdict = verdictOf(findings);
  const result = { findings, notes, verdict, fixes, version: pkg.version };
  fs.writeFileSync(path.join(root, 'SHIP-REPORT.md'), renderMarkdown(result));
  console.log(renderTerminal(result));
  return verdict === 'DO_NOT_SHIP' ? 1 : 0;
}

const args = process.argv.slice(2);
const cmd = args[0];
const root = process.cwd();

let exitCode = 0;
try {
  switch (cmd) {
    case 'setup':
      cmdSetup(root);
      break;
    case 'scan':
      exitCode = args.includes('--staged')
        ? cmdScanStaged(root, args.includes('--quiet'))
        : cmdScan(root);
      break;
    case 'ship': {
      const fixHistory = args.includes('--fix-history');
      // A history reset needs .gitignore in place first so the fresh commit
      // doesn't re-add .env — so --fix-history implies the additive fixes.
      exitCode = cmdShip(root, { fix: !args.includes('--no-fix') || fixHistory, fixHistory });
      break;
    }
    case '--version':
    case '-v':
      console.log(pkg.version);
      break;
    default:
      console.log(HELP);
      if (cmd && cmd !== 'help' && cmd !== '--help' && cmd !== '-h') {
        console.error(`Unknown command: ${cmd}`);
        exitCode = 1;
      }
  }
} catch (err) {
  // A raw stack trace here is exactly the wrong first impression for a
  // tool whose whole promise is "no security background needed" — this is
  // the difference between an unreadable crash (permission errors on
  // sandboxed/cloud IDEs are common) and a plain-English explanation.
  console.error(`\n  ShipClear hit an unexpected problem: ${err.message}`);
  console.error('  If this keeps happening, please report it: https://github.com/adamtimmerberg/ShipClear/issues\n');
  exitCode = 1;
}
process.exit(exitCode);
