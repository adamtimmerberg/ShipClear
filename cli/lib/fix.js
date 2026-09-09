import fs from 'node:fs';
import path from 'node:path';
import { hasRemote, branchNames, hasStash, hasIdentity, run as git } from './git.js';

// Single source for the block both `setup` and the auto-fix append. Ignores
// SHIP-REPORT.md too: a committed report is a map of exactly where the
// findings were ("secret at server.js:7, see commit e6c9969") — the last
// thing to hand a stranger reading a public repo.
export const GITIGNORE_BLOCK = `
# Secrets — added by ShipClear
.env
.env.*
!.env.example
SHIP-REPORT.md
`;

// The git pre-commit guard. Fails closed when the scan ran and found
// secrets (its output contains "ShipClear blocked"); fails open with a
// warning when the scanner itself couldn't run (offline npx, package not
// installed) — a guard that blocks every commit during an npm outage,
// with a wall of "npm error 404", gets deleted rather than fixed.
export const HOOK_SCRIPT = `#!/bin/sh
# Installed by ShipClear (shipclear setup). Blocks commits containing secrets.
# Remove this file to uninstall.
if [ -x "./node_modules/.bin/shipclear" ]; then
  out=$(./node_modules/.bin/shipclear scan --staged 2>&1); status=$?
else
  out=$(npx --yes shipclear scan --staged 2>&1); status=$?
fi
if [ "$status" -eq 0 ]; then exit 0; fi
case "$out" in
  *"ShipClear blocked"*) printf '%s\\n' "$out" >&2; exit 1 ;;
  *) printf 'ShipClear guard: could not run the staged scan (is shipclear installed / are you online?). Letting this commit through — run "npx shipclear scan --staged" yourself when you can.\\n' >&2; exit 0 ;;
esac
`;

/** Install (or refresh) the commit guard. Returns false if a foreign hook is in the way. */
export function installHook(root) {
  const hookDir = path.join(root, '.git', 'hooks');
  const hookPath = path.join(hookDir, 'pre-commit');
  if (fs.existsSync(hookPath) && !fs.readFileSync(hookPath, 'utf8').includes('ShipClear')) return false;
  fs.mkdirSync(hookDir, { recursive: true });
  fs.writeFileSync(hookPath, HOOK_SCRIPT, { mode: 0o755 });
  return true;
}

function hasOurHook(root) {
  const hookPath = path.join(root, '.git', 'hooks', 'pre-commit');
  return fs.existsSync(hookPath) && fs.readFileSync(hookPath, 'utf8').includes('ShipClear');
}

/** A .env.example built from .env's variable names with every value stripped. */
export function envExampleFrom(envPath) {
  const keys = fs.readFileSync(envPath, 'utf8')
    .split('\n')
    .map((l) => l.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/))
    .filter(Boolean)
    .map((m) => `${m[1]}=`);
  return '# Copy to .env and fill in real values. Never commit .env.\n' + keys.join('\n') + (keys.length ? '\n' : '');
}

/**
 * Apply the fixes that are safe to do without asking: they only ever add
 * protection, never delete or rewrite anything. Marks the corresponding
 * findings as resolved and returns descriptions of what was done.
 */
export function applyFixes(root, findings) {
  const applied = [];

  for (const finding of findings) {
    if (finding.id === 'gitignore-incomplete') {
      const file = path.join(root, '.gitignore');
      const existing = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
      fs.writeFileSync(file, existing + GITIGNORE_BLOCK);
      finding.resolved = true;
      applied.push('Added `.env` protection to .gitignore (created it if missing), and kept SHIP-REPORT.md out of git too.');
    }

    if (finding.id === 'env-example-missing') {
      fs.writeFileSync(path.join(root, '.env.example'), envExampleFrom(path.join(root, '.env')));
      finding.resolved = true;
      applied.push('Created .env.example with your variable names and no values.');
    }
  }

  return applied;
}

// Findings the reset itself cures: history is erased, and .env is no longer
// tracked once .gitignore (guaranteed by the implied additive fixes) excludes
// it from the fresh `git add -A`. Everything else that's still open would be
// re-added to the new root commit — baking it into history and forcing a
// second reset. A green verdict on a repo whose only commit holds four SSNs
// is the exact false-GO this project exists to prevent.
const CURED_BY_RESET = new Set(['secret-in-history', 'env-tracked']);

/**
 * The one destructive fix, and the only one that is opt-in
 * (`shipclear ship --fix-history`): erase git history so a leaked secret
 * that was committed then deleted stops living in old commits.
 *
 * Exists because the alternative — telling a first-time user to type
 * `rm -rf .git` by hand — is a real hazard (wrong directory, nothing
 * checking for branches or stashes they'd lose). Running it here means it
 * runs on exactly the folder ShipClear just scanned, and refuses in every
 * situation where "start fresh" would silently destroy something — or
 * silently preserve something it shouldn't.
 *
 * Returns { done } on success or { refused } with a plain-English reason.
 * Never touches the key itself — rotation is still the user's job.
 */
export function resetHistory(root, findings) {
  const targets = findings.filter((f) => f.id === 'secret-in-history' && !f.resolved);
  if (!targets.length) return { refused: 'there are no git-history findings to fix.' };

  const wouldBeBakedIn = findings.filter(
    (f) => !f.resolved && !CURED_BY_RESET.has(f.id) && ['critical', 'high', 'medium'].includes(f.severity)
  );
  if (wouldBeBakedIn.length) {
    const list = [...new Set(wouldBeBakedIn.map((f) => f.file ? `${f.file}` : f.id))].join(', ');
    return { refused: `other findings are still open (${list}). A fresh start saves whatever is in your project right now as the new first commit — so fix those first, then run --fix-history last. Otherwise they'd end up in history and you'd have to do this twice.` };
  }
  if (hasRemote(root)) {
    return { refused: 'this repo has a remote configured, so old commits may already exist somewhere else — erasing local history would not remove them. Use the steps in the "secret exists in your git history" finding above instead: paste its sentence to your AI assistant, or follow the do-it-yourself commands.' };
  }
  const branches = branchNames(root);
  if (branches.length > 1) {
    return { refused: `this repo has ${branches.length} branches (${branches.join(', ')}) and a reset keeps only the current one. Merge or delete the others first, then run this again.` };
  }
  if (hasStash(root)) {
    return { refused: 'this repo has stashed changes (`git stash list`) that a reset would lose. Apply or drop them first, then run this again.' };
  }

  const hadGuard = hasOurHook(root);
  fs.rmSync(path.join(root, '.git'), { recursive: true, force: true });
  git(root, ['init', '-q']);
  let identityNote = '';
  if (!hasIdentity(root)) {
    // Local to this repo only — never touches the user's global git config.
    git(root, ['config', 'user.email', 'you@example.com']);
    git(root, ['config', 'user.name', 'You']);
    identityNote = ' Git had no name/email set, so a placeholder was configured for this project only (optional to change — it only affects how your name shows on commits: `git config user.name "Your Name"`).';
  }
  git(root, ['add', '-A']);
  // Plain message on purpose: this becomes the first line of public history
  // if the repo is pushed, and shouldn't announce that there was a leak.
  git(root, ['commit', '-q', '-m', 'Fresh start']);
  // Keep the branch name the user had (main vs master) — a silent rename
  // would look like something went wrong. Best-effort: cosmetic only.
  if (branches[0]) {
    try { git(root, ['branch', '-M', branches[0]]); } catch { /* fine on any git that refuses */ }
  }
  // rm -rf .git took the commit guard with it. Put it back.
  const guardNote = hadGuard && installHook(root) ? ' The commit guard was reinstalled.' : '';
  for (const f of targets) f.resolved = true;
  return {
    done: `Reset git history to remove the leaked secret from old commits — your files are untouched, only the old commits are gone.${guardNote}${identityNote} You still need to rotate the key.`,
  };
}
