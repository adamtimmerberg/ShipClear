import fs from 'node:fs';
import path from 'node:path';

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt',
  'vendor', '__pycache__', 'venv', '.venv', 'coverage', 'target',
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
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(abs);
      } else if (entry.isFile()) {
        results.push(path.relative(root, abs).split(path.sep).join('/'));
      }
    }
  };
  walk(root);
  return results;
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
