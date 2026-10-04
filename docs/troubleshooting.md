# Troubleshooting & plain-English glossary

Stuck on something ShipClear said? This page answers the questions real first-time users actually hit, in plain language. Nothing here assumes you're a programmer.

If your question isn't here, paste ShipClear's output (it never includes your secret values — those are masked) into any AI chat like ChatGPT, Claude.ai, or Gemini and ask "what does this mean and what do I do?"

---

## "It says `command not found`"

- If the command started with **`npx`**: you need [Node.js](https://nodejs.org) installed — it's the free program that runs `npx`. Download the "LTS" version, install it like any app, restart your terminal, and try again.
- If it was a **different** command (like `pip`, `bfg`, or `git`): that specific program isn't installed. Node.js won't fix it — installing that program (or using the "ask your AI assistant" route ShipClear offers) will.

## "It told me to `commit`, but I don't know how"

"Commit" means "save this change into git's history." The command is:

```
git add -A && git commit -m "describe what you changed"
```

If git then says **"Please tell me who you are"**, it's a one-time setup — run the two lines it prints (they start with `git config`), then run the commit again.

## "`pip install git-filter-repo` failed with `externally-managed-environment`"

This is common on newer Macs and Linux. Two easy ways around it:

- Try `pipx install git-filter-repo` instead, or `pip install --user git-filter-repo`.
- Or don't bother — use the **"ask your AI assistant"** route ShipClear offers for that finding. It doesn't need any of this installed.

## "I ran `shipclear ship` after cleaning up, and it STILL shows the same finding"

If the finding was **a secret in git history** and you cleaned it using a tool like BFG or git-filter-repo: those tools clean the copy on GitHub, but your **own folder still has the old history**. Sync your folder to the cleaned version:

```
git fetch && git reset --hard origin/main
```

(Replace `main` with `master` if that's your branch.) Then run `shipclear ship` again.

## "git printed `rm '.env'` / `delete mode ...` — did I just delete my file?"

No. `git rm --cached` only tells git to **stop tracking** the file — the file stays safely on your computer. The scary-looking "rm" and "delete" words refer to git's records, not your actual files.

## "The commit guard let my commit through with a warning about being offline"

The guard blocks commits that contain secrets. But if it can't run its check at all (you're offline, or the tool isn't fully installed), it lets the commit through with a warning rather than blocking your work forever. It fails *safe*, not *stuck*. When you're back online, run `npx shipclear scan --staged` yourself to check.

## "The report has a checklist full of words I don't understand"

That's the "Semantic checks" section at the bottom of `SHIP-REPORT.md`, and it's meant for an AI, not for you to decode. Paste it and your code into any AI chat (ChatGPT, Claude.ai, Gemini — a free one is fine) and ask it to work through the list. Or ask a developer friend.

## "How do I put a secret in `.env` and read it in my code?"

1. Put the value in the `.env` file, one per line: `MY_KEY=the-actual-value`
2. In your code, read it with `process.env.MY_KEY` (JavaScript) or `os.environ["MY_KEY"]` (Python).
3. Most frameworks load `.env` automatically. **Plain Node.js does not** — either run your app with `node --env-file=.env yourapp.js`, or add `require('dotenv').config()` at the top (after `npm install dotenv`).

## "It found a hardcoded login and I deleted it — now my login page is broken"

Expected. Deleting the fake account also removed what your login checked against, so you need a *real* login system now. The easiest path: ask the AI assistant you built the app with to "replace the hardcoded login with a real login system." (Common choices it might use: Supabase Auth, Clerk, Auth0, NextAuth — but you don't have to choose; it can.)

## "My badge says `no status` / is grey"

Nothing has been checked yet, and the badge is saying so rather than guessing. It turns green or red after the first push that runs the workflow — check the **Actions** tab of your repo on GitHub. If no run appears there at all: make sure you committed **and pushed** `.github/workflows/shipclear.yml`, and that Actions is enabled for the repo (Settings → Actions → General).

## "My badge went red but `shipclear ship` passes on my computer"

Three usual reasons, in order of likelihood:

1. **You haven't pushed your fix yet.** The badge grades what's on GitHub, not what's on your laptop. `git add -A && git commit -m "fix" && git push`.
2. **The findings aren't critical.** The badge requires a full ✅ CLEARED. Plain `shipclear ship` exits successfully on 🟡 SHIP WITH FIXES so a human can decide — the badge can't decide, so it demands a clean pass. Run `npx shipclear ship --no-fix --strict` to see exactly what the badge sees.
3. **`shipclear ship` fixed something for you locally, and the fix isn't committed.** The gate applies safe fixes (like adding `.env` to `.gitignore`) and then reports you clean. GitHub gets the unfixed version, so it reports the finding. `git status` will show the changed files — commit them.

## "Can I just put the green badge in my README myself?"

You can, but it would be a lie the first time you push something unchecked, and anyone reading your repo can click the badge and see there's no run behind it. That's exactly why `shipclear badge` installs a real check instead of handing you a green image.

---

## Mini-glossary

- **Terminal** — the text window where you type commands instead of clicking. (In Bolt/Lovable/Replit, look for a "Terminal" or "Console" tab; on Mac, the Terminal app; on Windows, PowerShell.)
- **git** — the tool that tracks the history of your project's files. "Committing" saves a version; "pushing" sends it to GitHub.
- **commit** — one saved version of your project in git's history.
- **remote / origin** — the copy of your project on GitHub (or similar). "Already pushed" means a copy exists there.
- **`.gitignore`** — a list of files git should never save/share (like `.env`).
- **`.env`** — a private file holding your real secret values. It stays on your machine and should never be committed.
- **`.env.example`** — a safe-to-share template: the same setting *names* as `.env`, but with the values blank.
- **rotate a key** — get a brand-new key from whoever issued it (e.g. log into OpenAI and generate a new one) and stop using the old one. This is what actually protects you after a leak.
- **force-push** — overwrite the copy of history on GitHub with your cleaned-up local version. Fine for a repo only you work on.
