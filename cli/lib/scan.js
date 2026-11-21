import fs from 'node:fs';
import path from 'node:path';

// Build output, vendored dependencies and tool caches. Skipped at any depth:
// none of it is the user's code, and a cache can sit anywhere in a tree.
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt',
  'vendor', '__pycache__', 'venv', '.venv', 'coverage', 'target',
  'site-packages', '.tox', '.mypy_cache', '.pytest_cache', '.ruff_cache',
  '.cache', '.npm', '.nvm', '.pnpm-store', '.yarn', '.gradle', '.terraform',
]);

// Per-user tool state, skipped ONLY at the scan root. The scan root is just
// wherever the user ran the command, so it can be a home directory — and
// `.cache` + `.claude` + `.hermes` there contribute tens of thousands of
// findings from other people's vendored source.
//
// Root-only, not any-depth, on purpose: a project that has committed its own
// `.ssh/id_rsa` or `.docker/config.json` is precisely what this tool exists to
// catch, and skipping those names everywhere would turn the loudest real
// finding into silence. See wiki/gotchas/scan-root-is-cwd.md.
const ROOT_ONLY_SKIP_DIRS = new Set([
  '.ssh', '.gnupg', '.docker', '.aws', '.kube',
  '.local', '.config', '.claude', '.hermes', '.pm2', '.pii_shield',
  '.vscode-server', '.cargo', '.gem', '.rustup', '.m2', '.ivy2',
]);

const BINARY_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svgz',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.zip', '.gz', '.tar', '.rar', '.7z',
  '.pdf', '.mp3', '.mp4', '.mov', '.avi',
  '.sqlite', '.db', '.bin', '.exe', '.dll', '.so', '.dylib',
  '.pyc', '.class', '.jar', '.wasm',
]);

const MAX_FILE_BYTES = 2 * 1024 * 1024;

/** Walk a directory tree, returning relative paths of candidate files. */
export function walkFiles(root) {
  const results = [];
  const walk = (dir, atRoot) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (atRoot && ROOT_ONLY_SKIP_DIRS.has(entry.name)) continue;
        walk(abs, false);
      } else if (entry.isFile()) {
        results.push(path.relative(root, abs).split(path.sep).join('/'));
      }
    }
  };
  walk(root, true);
  return results;
}

/**
 * Whether a path lies inside a directory the walker skips. Exported so the
 * untracked-file sweep can apply the same rule: a project that hasn't
 * git-ignored node_modules would otherwise hand the gate every vendored file.
 */
export function isSkippedPath(rel) {
  const segments = rel.split('/');
  if (segments.some((segment) => SKIP_DIRS.has(segment))) return true;
  return segments.length > 1 && ROOT_ONLY_SKIP_DIRS.has(segments[0]);
}

export function isTextCandidate(rel) {
  return !BINARY_EXT.has(path.extname(rel).toLowerCase());
}

/** Read a file as UTF-8, or null if missing, too large, or unreadable. */
export function readFileSafe(absPath) {
  try {
    const stat = fs.statSync(absPath);
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) return null;
    return fs.readFileSync(absPath, 'utf8');
  } catch {
    return null;
  }
}
