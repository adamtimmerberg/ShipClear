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

export function trackedFiles(root) {
  return git(root, ['ls-files']).split('\n').filter(Boolean);
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
 * secret that was committed and later deleted is still found.
 * Returns [{ commit, file, text }].
 */
export function historyAddedLines(root) {
  const out = git(root, [
    'log', '--all', '-p', '--unified=0', '--no-color',
    '--pretty=format:@@shipclear-commit@@ %h',
  ]);
  const added = [];
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
      added.push({ commit, file, text: line.slice(1) });
    }
  }
  return added;
}
