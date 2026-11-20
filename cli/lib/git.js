import { execFileSync } from 'node:child_process';

function git(root, args, opts = {}) {
  return execFileSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...opts,
  });
}

export function isGitRepo(root) {
  try {
    return git(root, ['rev-parse', '--is-inside-work-tree']).trim() === 'true';
  } catch {
    return false;
  }
}

export function hasCommits(root) {
  try {
    git(root, ['rev-parse', 'HEAD']);
    return true;
  } catch {
    return false;
  }
}

/** Whether this repo has any remote configured (e.g. pushed to GitHub). */
export function hasRemote(root) {
  try {
    return git(root, ['remote']).trim().length > 0;
  } catch {
    return false;
  }
}

export function branchNames(root) {
  try {
    return git(root, ['branch', '--format=%(refname:short)']).split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

export function hasStash(root) {
  try {
    return git(root, ['stash', 'list']).trim().length > 0;
  } catch {
    return false;
  }
}

/** Whether git has a user identity it could commit with (global or local). */
export function hasIdentity(root) {
  try {
    return git(root, ['config', 'user.email']).trim().length > 0;
  } catch {
    return false;
  }
}

export function run(root, args) {
  return git(root, args);
}

export function trackedFiles(root) {
  return git(root, ['ls-files']).split('\n').filter(Boolean);
}

/**
 * Files git is not tracking and not ignoring — exactly what `git add -A`
 * would add next. The gate has to judge these: the realistic beginner order
 * is build → `shipclear ship` → `git add -A && commit && push`, so a brand
 * new file is precisely the one a verdict is asked about.
 */
export function untrackedFiles(root) {
  try {
    return git(root, ['ls-files', '--others', '--exclude-standard']).split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

export function stagedFiles(root) {
  return git(root, ['diff', '--cached', '--name-only', '--diff-filter=ACM'])
    .split('\n')
    .filter(Boolean);
}

/** Content of a file as staged in the index (what a commit would record). */
export function stagedContent(root, file) {
  try {
    return git(root, ['show', ':' + file]);
  } catch {
    return null;
  }
}

/**
 * Every line ever *added* across the full history of all branches, so a
 * secret that was committed and later deleted is still found. Added lines are
 * grouped per commit+file, which is also how findings are reported.
 *
 * The grouping is load-bearing, not tidiness: handing detectors one line at a
 * time makes any pattern that needs more than one line silently blind in
 * history. Private key material is exactly that shape — a PEM header is only
 * a leak when its base64 body follows — so a per-line feed would have found
 * every leaked key file in the working tree and none in the history, which is
 * the half that matters once a secret has been deleted.
 * Returns [{ commit, file, text }].
 */
export function historyAddedLines(root) {
  const out = git(root, [
    'log', '--all', '-p', '--unified=0', '--no-color',
    '--pretty=format:@@shipclear-commit@@ %h',
  ]);
  const blocks = new Map();
  const order = [];
  let commit = null;
  let file = null;
  for (const line of out.split('\n')) {
    if (line.startsWith('@@shipclear-commit@@ ')) {
      commit = line.slice('@@shipclear-commit@@ '.length).trim();
    } else if (line.startsWith('+++ b/')) {
      file = line.slice('+++ b/'.length);
    } else if (line.startsWith('+++ /dev/null')) {
      file = null;
    } else if (line.startsWith('+') && !line.startsWith('+++') && file) {
      const key = `${commit}\u0000${file}`;
      if (!blocks.has(key)) {
        blocks.set(key, { commit, file, lines: [] });
        order.push(key);
      }
      blocks.get(key).lines.push(line.slice(1));
    }
  }
  return order.map((key) => {
    const b = blocks.get(key);
    return { commit: b.commit, file: b.file, text: b.lines.join('\n') };
  });
}
