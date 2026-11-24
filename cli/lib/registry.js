// The list of checks the gate runs, and the single source of how many there
// are. Nothing here hardcodes a count: the banner, the tally, the report and
// the docs test all read REGISTRY.length, so adding a check below is the
// whole job of adding a check.
//
// Pure data and predicates on purpose — it imports nothing from checks.js, so
// the drift test can read it without pulling in the scanner.
import fs from 'node:fs';
import path from 'node:path';

const exists = (root, ...names) => names.find((n) => fs.existsSync(path.join(root, n))) || null;

const NEEDS_GIT = (ctx) =>
  (ctx.inGit ? null : 'this folder is not a git repository yet, so nothing is tracked');

// Which package manager's lockfile is present decides whether the built-in
// dependency check can run at all. Telling a pnpm or yarn project to run
// `npm install` would create a second, competing lockfile in their repo, so
// those get pointed at osv-scanner instead.
const ALT_LOCKFILES = {
  'pnpm-lock.yaml': 'pnpm',
  'yarn.lock': 'yarn',
  'bun.lockb': 'bun',
  'bun.lock': 'bun',
};
const PY_MANIFESTS = ['requirements.txt', 'Pipfile', 'pyproject.toml', 'poetry.lock'];
const OTHER_MANIFESTS = {
  'Gemfile': 'bundler-audit',
  'go.mod': 'govulncheck',
  'Cargo.toml': 'cargo audit',
  'composer.json': 'composer audit',
};

// Installing osv-scanner is the one move that fixes every ecosystem at once:
// ShipClear picks it up automatically on the next run, no flags, no config.
// Three routes because the audience spans a Mac with Homebrew, a Go
// developer, and someone on Windows who has never installed a binary.
const OSV_INSTALL = [
  'Or install osv-scanner once and ShipClear checks your dependencies every run from then on:',
  '  • macOS or Linux with Homebrew: `brew install osv-scanner`',
  '  • If you have Go: `go install github.com/google/osv-scanner/cmd/osv-scanner@latest`',
  '  • Windows, or neither of those: download it from',
  '    https://github.com/google/osv-scanner/releases and put it somewhere on your PATH',
];
const THEN_RERUN = 'Then run `shipclear ship` again — the check will be in the list.';

// What the user can actually type, per situation. Printed only when the
// check did not run, because a list of install steps under a check that
// already ran is noise.
const AUDIT_COMMAND = {
  pnpm: '`pnpm audit`',
  yarn: '`yarn npm audit` (on Yarn 1, it is `yarn audit`)',
  bun: '`bun audit`, if your version of Bun has it',
};

function dependencySkip(ctx) {
  if (ctx.has('osv-scanner')) return null;
  if (exists(ctx.root, 'package-lock.json')) return null;

  const alt = Object.keys(ALT_LOCKFILES).find((f) => fs.existsSync(path.join(ctx.root, f)));
  if (alt) {
    const manager = ALT_LOCKFILES[alt];
    return {
      reason: `this project uses ${manager}, and ShipClear's built-in dependency check reads npm's package-lock.json only — so your dependencies were not checked for known vulnerabilities. (Do not run \`npm install\` to create a package-lock.json here: it would add a second, competing lockfile to a ${manager} project.)`,
      steps: [
        `Right now, with nothing to install: ${AUDIT_COMMAND[manager]}`,
        ...OSV_INSTALL,
        THEN_RERUN,
      ],
    };
  }
  if (exists(ctx.root, 'package.json')) {
    return {
      reason: 'no package-lock.json, so your dependencies were not checked for known vulnerabilities.',
      steps: [
        'Create the file npm reads, which also installs your packages: `npm install`',
        'Then run `shipclear ship` again — the check runs on its own from then on.',
        '(If your package.json has no "dependencies" section, there is genuinely nothing to check.)',
      ],
    };
  }
  if (PY_MANIFESTS.some((f) => fs.existsSync(path.join(ctx.root, f)))) {
    return {
      reason: "this looks like a Python project and ShipClear's built-in dependency check is npm-only, so your packages were not checked for known vulnerabilities.",
      steps: [
        'Right now: `pip install pip-audit` then `pip-audit` in this folder',
        ...OSV_INSTALL,
        THEN_RERUN,
      ],
    };
  }
  const manifest = Object.keys(OTHER_MANIFESTS).find((f) => fs.existsSync(path.join(ctx.root, f)));
  if (manifest) {
    return {
      reason: `ShipClear's built-in dependency check is npm-only, so the packages in ${manifest} were not checked for known vulnerabilities.`,
      steps: [
        `Right now: \`${OTHER_MANIFESTS[manifest]}\` in this folder`,
        ...OSV_INSTALL,
        THEN_RERUN,
      ],
    };
  }
  return 'no dependency manifest found in this project, so there is nothing to check.';
}

/**
 * One entry per check.
 *   id     — stable key; also the key of its runner in checks.js
 *   label  — what the user sees on the progress line
 *   skip   — null, a reason string, or { reason, steps } where steps are the
 *            literal commands that would turn this check on. Steps print only
 *            when the check did not run.
 *   emits  — every finding id this check can raise (pinned by a drift test
 *            against report.js's EXPLAIN, so a new finding cannot be added
 *            without being attributed to a check)
 *   quick  — also runs in `shipclear scan`; everything else is full-gate only
 *   skip   — reason string when this check cannot run here, else null
 */
export const REGISTRY = [
  { id: 'secrets-in-code', label: 'Secrets written in your code', emits: ['secret-in-code', 'generic-secret'], quick: true },
  { id: 'hardcoded-logins', label: 'Logins hardcoded in your code', emits: ['test-account'] },
  { id: 'tls-verification-off', label: 'Certificate checking switched off', emits: ['tls-verification-off'] },
  { id: 'debug-mode-on', label: 'Debug mode left on', emits: ['debug-mode-on'] },
  { id: 'personal-paths', label: 'Your own file paths leaking into the repo', emits: ['personal-path'] },
  { id: 'committed-env-files', label: 'Committed .env files', emits: ['env-tracked'], quick: true, skip: NEEDS_GIT },
  { id: 'committed-key-files', label: 'Committed private key files', emits: ['key-file-tracked'], quick: true, skip: NEEDS_GIT },
  { id: 'committed-test-logins', label: "ShipClear's test-login store, committed", emits: ['test-account'], quick: true, skip: NEEDS_GIT },
  { id: 'agent-artifacts', label: 'AI session files in the repo', emits: ['agent-artifact'], quick: true, skip: NEEDS_GIT },
  { id: 'uncommitted-key-files', label: 'Key files your next commit would sweep in', emits: ['key-file-uncommitted'], quick: true },
  { id: 'gitignore-coverage', label: '.gitignore protects your .env', emits: ['gitignore-incomplete'], quick: true },
  { id: 'env-example-leak', label: 'Real values in .env.example', emits: ['env-example-leak'] },
  { id: 'pii-data-files', label: 'Personal data in data files', emits: ['pii-data-file'] },
  {
    id: 'secrets-in-history',
    label: 'Secrets anywhere in your git history',
    emits: ['secret-in-history'],
    skip: (ctx) => NEEDS_GIT(ctx) || (ctx.hasCommits ? null : 'this repository has no commits yet, so there is no history to scan'),
  },
  { id: 'credential-in-use-is-public', label: 'Live credentials that are public knowledge', emits: ['credential-in-use-is-public'] },
  { id: 'secret-default-fallback', label: 'Secrets that fall back to a known value', emits: ['secret-default-fallback'] },
  { id: 'public-bucket', label: 'Storage anyone can read or list', emits: ['public-bucket'] },
  { id: 'proxy-exposes-service', label: 'Public routes into a backing service', emits: ['proxy-exposes-service'] },
  { id: 'debug-route-public', label: 'Debug and metrics pages with no login', emits: ['debug-route-public'] },
  { id: 'headers-html-uncovered', label: 'Security headers on your pages, not just your API', emits: ['headers-html-uncovered'] },
  { id: 'ssrf-unchecked-fetch', label: 'A server that will fetch any address it is given', emits: ['ssrf-unchecked-fetch'] },
  { id: 'test-registry-present', label: 'Generated test logins awaiting cleanup', emits: ['test-registry-present'] },
  { id: 'env-example-missing', label: 'An .env.example template for collaborators', emits: ['env-example-missing'] },
  {
    id: 'deep-secret-scan',
    label: 'Deeper secret scan (gitleaks)',
    emits: ['secret-in-code'],
    skip: (ctx) => (ctx.has('gitleaks') ? null : 'gitleaks is not installed. It is optional — ShipClear\'s own secret scan ran either way; gitleaks would add a second, deeper pass on top of it'),
  },
  {
    id: 'dependency-vulns',
    label: 'Known-vulnerable dependencies',
    emits: ['dependency-vulns'],
    skip: dependencySkip,
  },
];

export const QUICK_SKIP_REASON =
  'this is the quick scan; the check needs the full gate — run `shipclear ship`';

export const byId = (id) => REGISTRY.find((c) => c.id === id);
