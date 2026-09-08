import fs from 'node:fs';
import path from 'node:path';

const GITIGNORE_BLOCK = `
# Secrets — added by ShipClear
.env
.env.*
!.env.example
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
      applied.push('Added `.env` protection to .gitignore (created it if missing).');
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
