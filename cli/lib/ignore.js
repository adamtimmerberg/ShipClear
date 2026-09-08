import fs from 'node:fs';
import path from 'node:path';

const ALWAYS_IGNORED = ['SHIP-REPORT.md'];

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Load .shipclearignore (one path or simple glob per line, # comments) and
 * return a matcher over repo-relative paths. Directory entries cover
 * everything beneath them.
 */
export function loadIgnore(root) {
  const patterns = [...ALWAYS_IGNORED];
  const file = path.join(root, '.shipclearignore');
  if (fs.existsSync(file)) {
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) patterns.push(trimmed);
    }
  }
  const rules = patterns.map((raw) => {
    const pat = raw.replace(/\/+$/, '');
    if (pat.includes('*')) {
      const rx = new RegExp('^' + pat.split('*').map(escapeRegex).join('[^/]*') + '(/.*)?$');
      return (rel) => rx.test(rel);
    }
    return (rel) => rel === pat || rel.startsWith(pat + '/');
  });
  return (rel) => rules.some((rule) => rule(rel));
}
