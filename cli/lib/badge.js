// The README badge.
//
// A badge is a security claim, so it is held to the same standard as a
// verdict: it must never say "cleared" for code nobody checked. That rules
// out the obvious implementation. A static image —
// `shields.io/badge/ShipClear-cleared%20to%20ship-brightgreen` — is a
// hardcoded green picture: paste it once and it keeps making the claim on
// every later commit, whether or not the gate ever ran again. That is a
// false GO, the one failure mode this product exists to prevent
// (CONTRIBUTING.md), and ShipClear used to hand it to users itself.
//
// The honest version has to be computed by something that runs on every
// push and that the author cannot skip by forgetting. On GitHub that is
// GitHub Actions. So `shipclear badge` installs a workflow whose only job
// is the verdict, and a badge that renders that workflow's real status:
//
//   green  — the latest push to this branch cleared the gate
//   red    — it did not clear
//   grey   — nothing ran ("no status"), so nothing is claimed
//
// Two flags in the workflow carry the whole guarantee:
//   --no-fix  the verdict must describe the commit as pushed, not a copy
//             the job quietly repaired on its way past (plain `ship` would
//             add the missing .gitignore line itself and then report clean)
//   --strict  only a CLEARED verdict may show green (plain `ship` exits 0
//             on SHIP WITH FIXES, which would paint HIGH findings green)
//
// "Every commit was cleared" holds rather than just "the last one did",
// because the gate reads git history: a secret committed at any point keeps
// failing at HEAD until the history is actually cleaned.
import fs from 'node:fs';
import path from 'node:path';
import { run } from './git.js';

export const WORKFLOW_REL = '.github/workflows/shipclear.yml';

// The release that introduced `--strict`. The workflow must pin at least
// this, because unknown flags are silently ignored: run `ship --no-fix
// --strict` on 1.0.0 and you get plain `ship --no-fix`, which exits 0 on
// SHIP WITH FIXES — a green badge for a repo with HIGH findings. Verified
// against the published 1.0.0, not assumed. A caret range still picks up
// later 1.x releases, so the badge keeps reflecting current knowledge.
export const MIN_CLI_VERSION = '1.1.0';

/** owner/repo from the origin remote, or null if it isn't a GitHub remote. */
export function githubSlug(root) {
  let url;
  try {
    url = run(root, ['remote', 'get-url', 'origin']).trim();
  } catch {
    return null;
  }
  // https://github.com/o/r(.git) · git@github.com:o/r(.git) · ssh://git@github.com/o/r
  const m = url.match(/github\.com[:/]+([^/]+)\/([^/]+?)(?:\.git)?\/?$/i);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

export function currentBranch(root) {
  try {
    const b = run(root, ['rev-parse', '--abbrev-ref', 'HEAD']).trim();
    return b && b !== 'HEAD' ? b : 'main';
  } catch {
    return 'main';
  }
}

// Served by GitHub itself rather than a third-party image host, so the
// authority on whether the workflow passed is also the thing drawing the
// picture. `event=push` pins it to pushed code, so a green pull-request run
// can't speak for the branch; the label is the workflow's own name.
export function badgeMarkdown({ owner, repo, branch }) {
  const wf = `https://github.com/${owner}/${repo}/actions/workflows/shipclear.yml`;
  return `[![ShipClear](${wf}/badge.svg?branch=${encodeURIComponent(branch)}&event=push)](${wf})`;
}

export function workflowYaml() {
  return `# Keeps the ShipClear badge in this README honest.
#
# Re-runs the gate on GitHub for every push, so the badge reflects the code
# that is actually on GitHub — not whatever was on someone's laptop the last
# time they remembered to check. A commit ShipClear won't clear fails this
# job, and the badge turns red.
#
# --no-fix: judge the commit as pushed. Without it the job would apply the
#           safe fixes to its own checkout and report the repaired copy.
# --strict: only a clean CLEARED verdict passes. Without it "SHIP WITH
#           FIXES" would exit 0 and show green.
name: ShipClear

on:
  push:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # the gate scans your whole git history
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      # Pinned at or above the release that added --strict: an older CLI
      # ignores the flag silently and would exit 0 on findings. The caret
      # still takes later 1.x releases, so a security badge keeps
      # reflecting what is known to be unsafe today.
      - run: npx --yes shipclear@^${MIN_CLI_VERSION} ship --no-fix --strict
`;
}

const IMAGE_MD = /\[?!\[([^\]]*)\]\(([^)]*)\)(?:\]\([^)]*\))?/g;

// Which images are *our* badge. This has to be exact, not a "shipclear"
// substring search: in this very repo every badge URL contains
// github.com/adamtimmerberg/ShipClear, so a loose match replaced the CI
// badge instead (caught by running this command on its own README). Any
// user whose repo is named shipclear-something would have hit the same
// thing. Match the badge endpoint or the retired static badge, or an alt
// text that opens with the product name.
function isOurBadge(whole, alt, url) {
  return /\/actions\/workflows\/shipclear\.yml\/badge\.svg/i.test(url)
    || /shields\.io\/badge\/ShipClear/i.test(url)
    || /^\s*ShipClear\b/i.test(alt);
}

/** A line that is nothing but badges — the row to join if one exists. */
function isBadgeRow(line) {
  const stripped = line.replace(IMAGE_MD, '').trim();
  return stripped === '' && line.trim() !== '';
}

/**
 * Put `badge` in the README: replacing any badge already there (including
 * the old static image), else joining the badge row, else after the H1.
 * Pure string work so the placement is testable without a repo.
 */
export function withBadge(readme, badge) {
  for (const m of readme.matchAll(IMAGE_MD)) {
    if (!isOurBadge(m[0], m[1], m[2])) continue;
    if (m[0] === badge) return { text: readme, changed: false, how: 'already current' };
    return {
      text: readme.slice(0, m.index) + badge + readme.slice(m.index + m[0].length),
      changed: true,
      how: 'replaced the old badge',
    };
  }
  const lines = readme.split('\n');
  const row = lines.findIndex(isBadgeRow);
  if (row !== -1) {
    lines[row] = `${lines[row].trimEnd()} ${badge}`;
    return { text: lines.join('\n'), changed: true, how: 'added it to your badge row' };
  }
  const h1 = lines.findIndex((l) => /^#\s+\S/.test(l));
  if (h1 !== -1) {
    lines.splice(h1 + 1, 0, '', badge);
    return { text: lines.join('\n'), changed: true, how: 'added it under your title' };
  }
  return { text: [badge, '', readme].join('\n'), changed: true, how: 'added it at the top' };
}

/**
 * Install the workflow and the badge. Returns { ok:false, reason } when the
 * repo has nowhere for a live badge to point.
 */
export function installBadge(root) {
  const slug = githubSlug(root);
  if (!slug) {
    return {
      ok: false,
      reason: "this project has no GitHub remote, so there's nothing to publish a live badge from. Push it to GitHub first (create an empty repo there, then `git remote add origin <its URL>` and `git push -u origin HEAD`), then run `shipclear badge` again.",
    };
  }
  const branch = currentBranch(root);
  const badge = badgeMarkdown({ ...slug, branch });
  const done = [];
  const warnings = [];

  const wfPath = path.join(root, WORKFLOW_REL);
  if (!fs.existsSync(wfPath)) {
    fs.mkdirSync(path.dirname(wfPath), { recursive: true });
    fs.writeFileSync(wfPath, workflowYaml());
    done.push(`created ${WORKFLOW_REL} — it re-runs the gate on GitHub for every push, which is what keeps the badge honest`);
  } else {
    const existing = fs.readFileSync(wfPath, 'utf8');
    // Never silently overwrite someone's workflow — but a badge pointing at
    // a workflow missing these flags can show green for a repo that didn't
    // clear, so say so rather than leaving a quiet lie in place.
    if (!/--strict/.test(existing) || !/--no-fix/.test(existing)) {
      warnings.push(`${WORKFLOW_REL} already exists, so ShipClear left it alone — but it doesn't run \`shipclear ship --no-fix --strict\`, so the badge can show green for a repo that only partly cleared. Add those flags to that file.`);
    } else {
      done.push(`${WORKFLOW_REL} was already in place`);
    }
  }

  const readmePath = ['README.md', 'readme.md', 'README.markdown']
    .map((n) => path.join(root, n))
    .find((p) => fs.existsSync(p));
  if (!readmePath) {
    warnings.push(`no README.md found in this folder, so there was nothing to add the badge to. Create one and paste this line into it:\n${badge}`);
  } else {
    const before = fs.readFileSync(readmePath, 'utf8');
    const { text, changed, how } = withBadge(before, badge);
    if (changed) fs.writeFileSync(readmePath, text);
    done.push(changed
      ? `${path.basename(readmePath)} — ${how}`
      : `${path.basename(readmePath)} already has the current badge`);
  }

  return { ok: true, done, warnings, badge, branch, slug };
}
