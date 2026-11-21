#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import readline from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import { runGate } from '../lib/checks.js';
import { applyFixes, resetHistory, installHook, envExampleFrom, GITIGNORE_BLOCK } from '../lib/fix.js';
import { renderTerminal, renderMarkdown, verdictOf, VERDICT_TEXT } from '../lib/report.js';
import { findSecrets, maskSecret, lineOfIndex } from '../lib/patterns.js';
import { isGitRepo, stagedFiles, stagedContent } from '../lib/git.js';
import { installBadge } from '../lib/badge.js';
import { runProbe, normalizeBase } from '../lib/probe.js';
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
  shipclear ship --strict  Same, but treat ANY finding as a failure (exit 1 unless
                           the verdict is CLEARED) — for CI and the README badge
  shipclear ship --probe https://your-app.com
                           Also ask your deployed site what is actually
                           reachable: open debug pages, a storage folder anyone
                           can list, missing page headers. Read-only (GET
                           only), asks you to confirm first, and only ever
                           touches the address you type. Add --yes to skip the
                           confirmation (for scripts).
  shipclear ship --fix-history
                           Also erase git history to remove a leaked secret from
                           old commits (only when nothing was ever pushed; refuses
                           if it would lose branches or stashes)
  shipclear badge          Add a self-updating "cleared to ship" badge to your
                           README, backed by a GitHub Actions run of this gate on
                           every push — so it turns red if an unchecked or failing
                           commit lands
  shipclear --version      Print the version you're running

Everything runs locally and nothing is ever uploaded. The one exception is
opt-in: --probe makes read-only requests to the single address you give it.
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

// The probe reaches out to the network, which nothing else in ShipClear does.
// So it is opt-in per run, it says exactly what it will do, and it asks —
// unless the user passed --yes, or there is no terminal to ask in (a CI job),
// where it declines rather than guessing.
async function confirmProbe(url) {
  const { base, error } = normalizeBase(url);
  if (error) {
    console.error(`\n  ${error}\n`);
    return null;
  }
  if (!process.stdin.isTTY) {
    return { base, confirmed: false, why: 'there is no terminal here to confirm in — re-run it yourself, or add --yes if you are scripting this' };
  }
  console.log('');
  console.log(`  --probe will make read-only requests to ${base}:`);
  console.log('    • GET only. Nothing is written, changed or deleted.');
  console.log('    • No logins, no passwords, no attempts to get past anything.');
  console.log('    • Only that address and paths under it — nowhere else.');
  console.log('    • It checks for open debug pages, a storage folder anyone can list,');
  console.log('      and whether your home page sends the headers that protect pages.');
  console.log('  Only do this against a site you own.');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question(`\n  Probe ${base}? (y/N) `);
  rl.close();
  return { base, confirmed: /^y(es)?$/i.test(answer.trim()), why: 'you answered no' };
}

async function cmdShip(root, { fix = true, fixHistory = false, strict = false, probeUrl = null, assumeYes = false } = {}) {
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

  if (probeUrl) {
    const decision = await confirmProbe(probeUrl);
    if (decision === null) {
      notes.push('--probe was not run: that address could not be read.');
    } else if (!decision.confirmed && !assumeYes) {
      notes.push(`--probe was not run: ${decision.why}. Everything above is from your files alone.`);
    } else {
      const probed = await runProbe(decision.base, findings);
      findings.push(...probed.findings);
      notes.push(...probed.notes);
    }
  }

  const verdict = verdictOf(findings);
  // Strict mode exists for the README badge and CI: a badge may only be
  // green on a full CLEARED, so "SHIP WITH FIXES" — which exits 0 normally,
  // because a human can read it and decide — has to fail here.
  if (strict && verdict !== 'CLEARED') {
    notes.push('--strict: failing because the verdict is not CLEARED. Fix the findings above; a ShipClear badge stays red until they are gone.');
  }
  const result = { findings, notes, verdict, fixes, version: pkg.version };
  fs.writeFileSync(path.join(root, 'SHIP-REPORT.md'), renderMarkdown(result));
  console.log(renderTerminal(result));
  if (strict) return verdict === 'CLEARED' ? 0 : 1;
  return verdict === 'DO_NOT_SHIP' ? 1 : 0;
}

function cmdBadge(root) {
  if (!isGitRepo(root)) {
    console.error("\n  This folder isn't set up with git yet, so there's no GitHub repo for a badge to report on.");
    console.error('  Run `git init` here, push the project to GitHub, then run `shipclear badge` again.\n');
    return 1;
  }
  const result = installBadge(root);
  if (!result.ok) {
    console.error(`\n  ShipClear can't add the badge yet: ${result.reason}\n`);
    return 1;
  }
  console.log('\n  ShipClear badge installed.');
  for (const d of result.done) console.log(`   ✔ ${d}`);
  for (const w of result.warnings) console.log(`   ⚠ ${w}`);
  console.log('\n  Commit and push both files to switch it on:');
  console.log('    git add -A && git commit -m "add ShipClear badge" && git push');
  // The badge reads "no status" until the workflow has run once. Saying so
  // here stops that grey badge from looking like a broken install.
  console.log(`\n  It shows "no status" until that first push runs the workflow — grey because`);
  console.log('  nothing has been checked yet, which is the honest answer at that point.');
  console.log(`  Then it tracks the \`${result.branch}\` branch: green while every pushed commit`);
  console.log('  clears this gate, red the moment one does not.\n');
  return 0;
}

/** Value of a `--flag value` or `--flag=value` argument, or null. */
function flagValue(argv, flag) {
  const inline = argv.find((a) => a.startsWith(`${flag}=`));
  if (inline) return inline.slice(flag.length + 1) || null;
  const i = argv.indexOf(flag);
  if (i === -1) return null;
  const next = argv[i + 1];
  return next && !next.startsWith('-') ? next : null;
}

const args = process.argv.slice(2);
const cmd = args[0];
const root = process.cwd();

/**
 * The scan root is simply the working directory, so `shipclear` in the wrong
 * terminal tab points the whole gate at a home directory. That is not a
 * marginal mistake: a real run of this produced 34,330 findings, 99.4% of them
 * from `.cache`, `.claude` and `.hermes` — other people's vendored source —
 * and a 14.5 MB report whose verdict said DO NOT SHIP about nothing at all.
 *
 * SKIP_DIRS in lib/scan.js now drops those directories, but the honest fix is
 * to refuse the root outright: a home directory is not a project, and no
 * useful scan starts there.
 */
function refuseHomeDirectory(scanRoot) {
  const home = path.resolve(os.homedir());
  if (path.resolve(scanRoot) !== home) return false;
  console.error(`
  ShipClear is pointed at your home directory (${home}).

  That is almost always a wrong turn in the terminal rather than what you
  meant: a home directory holds package caches and other tools' state, not
  one project, so the scan would spend its time on vendored source that is
  not yours and report problems you cannot fix.

  Run it from inside the project you are shipping instead:

      cd ~/your-project
      shipclear ${cmd || 'ship'}
`);
  return true;
}

let exitCode = 0;
try {
  if (['scan', 'ship', 'setup', 'badge'].includes(cmd) && refuseHomeDirectory(root)) {
    process.exit(1);
  }
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
      exitCode = await cmdShip(root, {
        fix: !args.includes('--no-fix') || fixHistory,
        fixHistory,
        strict: args.includes('--strict'),
        probeUrl: flagValue(args, '--probe'),
        assumeYes: args.includes('--yes'),
      });
      break;
    }
    case 'badge':
      exitCode = cmdBadge(root);
      break;
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
