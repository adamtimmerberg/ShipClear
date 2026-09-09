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
      const envPath = path.join(root, '.env');
      const keys = fs.readFileSync(envPath, 'utf8')
        .split('\n')
        .map((l) => l.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/))
        .filter(Boolean)
        .map((m) => `${m[1]}=`);
      fs.writeFileSync(
        path.join(root, '.env.example'),
        '# Copy to .env and fill in real values. Never commit .env.\n' + keys.join('\n') + '\n'
      );
      finding.resolved = true;
      applied.push('Created .env.example with your variable names and no values.');
    }
  }

  return applied;
}

/**
 * The one destructive fix, and the only one that is opt-in
 * (`shipclear ship --fix-history`): erase git history so a leaked secret
 * that was committed then deleted stops living in old commits.
 *
 * Exists because the alternative — telling a first-time user to type
 * `rm -rf .git` by hand — is a real hazard (wrong directory, nothing
 * checking for branches or stashes they'd lose). Running it here means it
 * runs on exactly the folder ShipClear just scanned, and refuses in every
 * situation where "start fresh" would silently destroy something.
 *
 * Returns { done } on success or { refused } with a plain-English reason.
 * Never touches the key itself — rotation is still the user's job.
 */
export function resetHistory(root, findings) {
  const targets = findings.filter((f) => f.id === 'secret-in-history' && !f.resolved);
  if (!targets.length) return { refused: 'there are no git-history findings to fix.' };
  if (hasRemote(root)) {
    return { refused: 'this repo has a remote configured, so old commits may already exist somewhere else — erasing local history would not remove them. Follow the manual steps in the finding above instead.' };
  }
  const branches = branchNames(root);
  if (branches.length > 1) {
    return { refused: `this repo has ${branches.length} branches (${branches.join(', ')}) and a reset keeps only the current one. Merge or delete the others first, then run this again.` };
  }
  if (hasStash(root)) {
    return { refused: 'this repo has stashed changes (`git stash list`) that a reset would lose. Apply or drop them first, then run this again.' };
  }

  fs.rmSync(path.join(root, '.git'), { recursive: true, force: true });
  git(root, ['init', '-q']);
  let identityNote = '';
  if (!hasIdentity(root)) {
    // Local to this repo only — never touches the user's global git config.
    git(root, ['config', 'user.email', 'you@example.com']);
    git(root, ['config', 'user.name', 'You']);
    identityNote = ' Git had no name/email set, so a placeholder was configured for this project only — change it any time with `git config user.name "Your Name"` and `git config user.email "you@yours.com"`.';
  }
  git(root, ['add', '-A']);
  git(root, ['commit', '-q', '-m', 'Fresh start (history reset by ShipClear to remove a leaked secret)']);
  // Keep the branch name the user had (main vs master) — a silent rename
  // would look like something went wrong. Best-effort: cosmetic only.
  if (branches[0]) {
    try { git(root, ['branch', '-M', branches[0]]); } catch { /* fine on any git that refuses */ }
  }
  for (const f of targets) f.resolved = true;
  return {
    done: `Reset git history to remove the leaked secret from old commits — your files are untouched, only the old commits are gone.${identityNote} You still need to rotate the key.`,
  };
}
