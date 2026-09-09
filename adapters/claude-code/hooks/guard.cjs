#!/usr/bin/env node
// ShipClear commit guard (Claude Code PreToolUse hook).
// If the agent is about to run `git commit` or `git push`, scan the staged
// changes for secrets first. Exit 2 blocks the tool call; the message on
// stderr is shown to the agent so it can fix the problem instead.
//
// Written in Node (.cjs so it runs under any package "type") for Windows/
// macOS/Linux parity. Fails closed on findings, but open — with a warning —
// when the scanner itself can't run (offline npx, missing install): a guard
// that blocks every commit when the network is down gets uninstalled.
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

let input = '';
process.stdin.on('data', (d) => { input += d; });
process.stdin.on('end', () => {
  let command = '';
  try {
    command = JSON.parse(input)?.tool_input?.command || '';
  } catch {
    process.exit(0); // unparseable payload — never block on our own failure
  }
  if (!/\bgit\b[\s\S]*\b(commit|push)\b/.test(command)) process.exit(0);

  const win = process.platform === 'win32';
  const local = path.join('node_modules', '.bin', win ? 'shipclear.cmd' : 'shipclear');
  const [bin, args] = fs.existsSync(local)
    ? [local, ['scan', '--staged']]
    : ['npx', ['--yes', 'shipclear', 'scan', '--staged']];
  const result = spawnSync(bin, args, { shell: win, encoding: 'utf8' });

  if (result.status === 0) process.exit(0);

  const stderr = result.stderr || '';
  if (stderr.includes('ShipClear blocked')) {
    console.error(
      'ShipClear blocked this command: the staged changes contain secrets or a .env file.\n' +
      stderr.trim() + '\n' +
      'Move the secrets to .env, restage, then try again. Never bypass this by disabling the guard — fix the leak.'
    );
    process.exit(2);
  }

  // The scanner itself failed to run (offline, not installed, etc.) — warn,
  // don't brick every commit.
  console.error('ShipClear guard: could not run the staged scan (is shipclear installed?). Proceeding without it — run `npx shipclear scan --staged` manually when possible.');
  process.exit(0);
});
