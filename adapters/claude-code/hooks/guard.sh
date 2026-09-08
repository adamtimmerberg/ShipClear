#!/bin/sh
# ShipClear commit guard (Claude Code PreToolUse hook).
# If the agent is about to run `git commit` or `git push`, scan the staged
# changes for secrets first. Exit 2 blocks the tool call; the message on
# stderr is shown to the agent so it can fix the problem instead.
payload=$(cat)

case "$payload" in
  *"git commit"*|*"git push"*) ;;
  *) exit 0 ;;
esac

if [ -x "./node_modules/.bin/shipclear" ]; then
  scan="./node_modules/.bin/shipclear"
else
  scan="npx --yes shipclear"
fi

if ! $scan scan --staged --quiet >/dev/null 2>&1; then
  echo "ShipClear blocked this command: the staged changes contain secrets or a .env file. Run 'npx shipclear scan --staged' to see the findings, move the secrets to .env, then try again. Never bypass this by unstaging the scan — fix the leak." >&2
  exit 2
fi
exit 0
