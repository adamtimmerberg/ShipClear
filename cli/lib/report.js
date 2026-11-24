// Every finding gets three plain-English answers: what is this, why does it
// matter, what do I do. If an explanation needs jargon, it gets rewritten.
//
// Fix texts that name a file are functions of the finding, so the reader
// gets `git rm --cached signups.csv`, never `git rm --cached <file>` — an
// independent test showed that placeholder alone is enough to stall a
// first-time user. Every git step is a literal command: "commit" is not an
// instruction to someone who has never run git.
const untrackThenCommit = (file, what) =>
  `Run \`git rm --cached ${file}\` — that only stops git tracking it; the file stays on your machine (git will print \`rm '${file}'\`, which looks like a deletion but isn't). Then save that change: \`git commit -m "stop tracking ${what}"\`.`;

const dbUrlNote = ' (For a database URL, "the service" is wherever your database is hosted — change its password there.)';

// "Change its password there" is incomplete — and silently so — for a
// database running in a container: POSTGRES_PASSWORD and friends only apply
// the first time the data volume is created. Change the variable on a
// database that already has data and the old password keeps working, while
// the user believes they have rotated it.
const containerDbNote = (f) => (f.dbInContainer
  ? ' One more step, and it is easy to miss: changing this variable alone will NOT work if your database already has data — that variable only applies the first time the database is created. Do both: run `ALTER USER <your db user> WITH PASSWORD \'<new password>\';` against the database itself (`docker compose exec db psql -U <your db user>` gets you a prompt), and update the variable so a future rebuild matches. Then restart the services that connect to it.'
  : '');

const EXPLAIN = {
  'secret-in-code': {
    title: 'A secret key is written directly in your code',
    why: 'Anyone who sees this code — on GitHub, in a screenshot, in your deployed app — can use this key as you, and you get the bill.',
    fix: (f) => {
      const move = 'Move the value into your .env file and read it from an environment variable (`process.env.YOUR_KEY_NAME` in JavaScript, `os.environ["YOUR_KEY_NAME"]` in Python). Most frameworks (Next.js, Create React App, Django, Rails, and others) load .env automatically; plain Node.js does not — add `require(\'dotenv\').config()` at the top of your entry file (`npm install dotenv` first), or on Node 20+ run your app with `node --env-file=.env yourapp.js`.';
      // Rotation advice has to match reality: a file git has never recorded
      // has leaked nothing, and "this one is burned" about a key that never
      // left the laptop is the kind of inaccuracy that teaches people to
      // discount the next instruction.
      const rotate = f.uncommitted
        ? ' Good news on the key itself: this file has never been committed, so nothing has leaked and you do not need to rotate it — fixing it now means it never does. (If the value has been in a screenshot, a chat, or a paste anywhere, rotate anyway — it is free.)'
        : ' Then rotate the key: log in to the provider and generate a new one, because this one is burned.';
      return move + rotate + dbUrlNote + containerDbNote(f);
    },
  },
  'secret-in-history': {
    title: 'A secret exists in your git history',
    why: 'Deleting a key from your code does not delete it from git — every past version stays downloadable. If this repo goes public, the old key goes public with it.',
    // Varies by repo state. A static "use filter-repo or BFG" pointer was
    // the single thing that stopped the first independent test from ever
    // reaching a clean verdict; the second found the gaps in the hand-typed
    // path; the third found that running the reset *first* bakes every
    // other open finding into the new root commit — hence "do this last".
    fix: (f) => {
      const seeIt = `(Want to see exactly what leaked? Run \`git show ${f.commit || '<commit>'} -- ${f.file || '<file>'}\`.)`;
      const rotate = `Step 1 (does the actual protecting): rotate the key now — log in to whichever service issued it and generate a new one.${dbUrlNote}`;
      if (f.hasRemote) {
        const file = f.file || '<file>';
        // A whole-secrets file (.env, a key file) should vanish from history.
        // A secret *inside* a code file must be scrubbed while the file
        // stays — `--invert-paths` on bot.js would delete the user's program.
        const wholeFile = /(^|\/)\.env(\..+)?$|\.(pem|p12|pfx|ppk)$|(^|\/)id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$/.test(file);
        const askAi = wholeFile
          ? `"My git history contains a leaked secrets file, ${file}; remove that file from every commit with git filter-repo and force-push the cleaned history to origin."`
          : `"My git history contains a leaked API key inside ${file}; scrub that value from every commit with git filter-repo --replace-text (keep the file), then force-push the cleaned history to origin."`;
        const scrub = wholeFile
          ? `run \`git filter-repo --path ${file} --invert-paths --force\` (removes that file from every commit — it's git-ignored now, so it won't come back)`
          : `make a plain text file called \`secrets-to-remove.txt\` containing just the leaked value on one line (copy it from the \`git show\` command below), run \`git filter-repo --replace-text secrets-to-remove.txt --force\` (replaces that value with \`***REMOVED***\` in every commit; the file itself stays), then delete \`secrets-to-remove.txt\``;
        const branch = f.branch || 'main';
        // Multi-line: rendered as numbered steps (see the renderers). The
        // single-paragraph version of this was the #1 readability complaint
        // from two independent tests.
        return [
          rotate,
          "Once the key is rotated, the copy in history is useless to anyone — so if the next part gets hard, you are already safe; it's cleanup. (GitHub can keep an old commit reachable by its ID for a while, which is exactly why rotating is the step that matters.)",
          `Step 2 (cleanup): the old commit is also on the remote (your copy on GitHub), so erasing local history isn't enough. Two routes — pick one:`,
          `A) Easiest: ask the AI assistant you built this with. Paste it: ${askAi}`,
          `B) Do it yourself: install git filter-repo (it isn't part of git — try \`pipx install git-filter-repo\`, or \`pip install --user git-filter-repo\`, or \`brew install git-filter-repo\` on a Mac; if pip says "externally-managed-environment", use pipx, or just use route A — it needs none of this). Confirm with \`git filter-repo --version\` (any version number or short code means it's installed).`,
          `   Then: ${scrub}.`,
          `   Then re-add your remote (filter-repo removes it as a safety measure): \`git remote add origin <your repo url>\`, and \`git push --force origin ${branch}\` (this overwrites the copy on GitHub — fine for a repo only you work on; if anyone else cloned it, tell them first).`,
          `   Finally: \`shipclear ship\` again to confirm.`,
          `(BFG Repo-Cleaner is an alternative — needs Java, works on a separate "mirror" copy; if it prints a wall of text, the useful line starts with "Caused by:". It cleans GitHub but not your own folder, so finish with \`git fetch && git reset --hard origin/${branch}\` in your project, then \`shipclear ship\` again.)`,
          seeIt,
        ].join('\n');
      }
      return [
        rotate,
        "Step 2 (cleanup, and the easy one): this repo has never been pushed anywhere (no remote), so the fix is to erase git's memory and start fresh — every file stays exactly as it is, only old commits are forgotten.",
        'Do this LAST, after every other finding above is fixed — a fresh start saves your project exactly as it is right now, problems included.',
        'Easiest and safest: run `shipclear ship --fix-history` and ShipClear does it for you, in this folder, after checking it won\'t lose any other saved work.',
        'To do it by hand instead: `rm -rf .git && git init && git add -A && git commit -m "start"` (Mac/Linux; on Windows delete the `.git` folder first, then run the rest) — if git says "Please tell me who you are," run the two `git config` lines it shows you and repeat the commit.',
        seeIt,
      ].join('\n');
    },
  },
  'env-tracked': {
    title: 'Your .env file is checked into git',
    why: 'The .env file is your box of secrets. Committing it means every secret inside ships with the repo, forever, to everyone who can see it.',
    fix: (f) => `This was saved into git before ShipClear's protection was in place — setup stops it happening again, but can't undo the past. ${untrackThenCommit(f.file || '.env', 'secrets file')} Then rotate every key inside it — log in to each service and generate new ones.${dbUrlNote} One more thing: because it was committed, its contents are also in your git history — that's the separate "secret exists in your git history" finding, and \`shipclear ship --fix-history\` clears it once everything else is fixed.`,
  },
  'key-file-tracked': {
    title: 'A private key file is checked into git',
    why: 'Private key files (.pem, id_rsa and friends) are the literal keys to servers and services. Anyone with the repo can log in as you.',
    fix: (f) => `${untrackThenCommit(f.file || '<file>', 'key file')} Add its name (\`${f.file || '<file>'}\`) on its own line in .gitignore so it can't be re-added. Then replace the key itself: go back to wherever it came from (AWS, Firebase, your hosting provider, an SSH keygen) and create a new one — the committed one can never be trusted again, even after it's untracked.`,
  },
  'key-file-uncommitted': {
    title: 'A private key file is sitting in your project with nothing stopping git taking it',
    why: 'Private key files (.pem, id_rsa and friends) are the literal keys to servers and services. This one is not in git yet, so nothing has leaked — but nothing is preventing it either. The next `git add -A` sweeps it in, and once a key is in your history it is there in every future clone of the repo.',
    fix: (f) => `Add \`${f.file || '<file>'}\` on its own line in your .gitignore. That single line is the entire fix and it works immediately — the file stays exactly where it is on disk and your app keeps working; git simply stops offering to commit it. Check it worked: run \`git status --short\` and confirm \`${f.file || '<file>'}\` no longer appears. (If you also have a folder of certificates, ignoring the folder — \`certs/\` — is tidier than listing each file.)`,
  },
  'env-example-leak': {
    title: '.env.example contains a real-looking value',
    why: '.env.example is meant to be shared — it shows which settings exist, with the values blank. A real value here is a secret published on purpose.',
    fix: 'Replace the value with nothing (KEY=) or an obvious placeholder. If the value was real, rotate it — log in to whichever service issued it and generate a new one.',
  },
  'gitignore-incomplete': {
    title: '.env files are not protected by .gitignore',
    why: 'Without this, one ordinary `git add .` commits your secrets. This is the single most common way keys leak.',
    fix: 'Add a line with just `.env` (and `.env.*`) to your .gitignore file — or run `shipclear ship` again without `--no-fix` and ShipClear will add it for you.',
  },
  'pii-data-file': {
    title: 'A data file with real-looking personal information is in the repo',
    why: 'Emails, SSNs, and customer records in a repo become public the moment the repo does. That is a privacy breach, and in many places a legal one.',
    fix: (f) => `${untrackThenCommit(f.file || '<file>', 'data file')} Add its name (\`${f.file || '<file>'}\`) on its own line in .gitignore so it can't be re-added. If this is real data your app needs, that's fine — it stays on the machine where the app runs, just not in the repo (and if it's a list of people, it probably belongs in a database with proper access controls rather than a file). For testing and demos, use made-up data.`,
  },
  'test-account': {
    title: 'A login is hardcoded in the app',
    why: 'AI assistants often create accounts like admin@… "just for testing". If it ships, anyone who reads the code can log in to your live app with it.',
    fix: 'Delete the lines that define the credentials AND the lines that check against them — leaving the check behind makes login crash instead of merely not working. Then ask the AI assistant you built this with to replace it: tell it "replace the hardcoded login with a real login system." (If you want the names: Supabase Auth, Clerk, Auth0, and NextAuth are common choices — but you don\'t need to pick; your AI can.) If tests need an account, create it with random values at test time and keep them out of git.',
  },
  'dependency-vulns': {
    title: 'Dependencies have known security holes',
    why: 'These are published vulnerabilities with public write-ups — attackers scan for them automatically.',
    fix: 'Run `npm audit fix` and re-test the app. For anything it can\'t fix, `npm audit` names the package so you can update or replace it.',
  },
  'generic-secret': {
    title: 'A value that looks like a credential is hardcoded',
    why: 'Something named like a key, token, or password is assigned directly in the code. If it\'s real, it leaks with the repo.',
    fix: 'If it\'s a real credential: move it to .env and rotate it (log in to whichever service issued it and generate a new one). If it\'s a harmless placeholder, make it look like one (empty, or "REPLACE_ME") so scanners stay calm — or add the file to .shipclearignore.',
  },
  'debug-mode-on': {
    title: 'Debug mode is switched on',
    why: 'With debug mode on, anyone who triggers an error in your live app gets an interactive Python console in their browser — which is full control of your server. It is meant only for your own machine while building.',
    fix: 'This is fine while you build locally, but it must be off in the version that runs for real. Remove `debug=True` (or read it from an environment variable that is off in production). If your host runs the app for you, make sure it is not started in development mode.',
  },
  'tls-verification-off': {
    title: 'Certificate checking is switched off',
    why: 'This line tells your app to trust any server, even a fake one — so anyone on the same network (a café, a hotel) can sit between your app and the real service and read or change what passes through, including your API keys.',
    fix: 'Delete this line. It was almost certainly added to make a certificate error go away; the real fix is to solve that error (usually a wrong URL, a missing certificate on your own server, or a corporate proxy). If it was only for local testing, keep it out of the code that ships.',
  },
  'personal-path': {
    title: 'Your local file path (with your username) is in the code',
    why: 'Purely a privacy footprint: it reveals your computer\'s username and folder layout. Harmless to the app, but not something to publish.',
    fix: 'Use a relative path or an environment variable instead.',
  },
  'agent-artifact': {
    title: 'AI-tool working files are checked into git',
    why: 'Local agent settings and session files can contain machine details, and occasionally pasted secrets. They are your workspace, not your product.',
    fix: (f) => `Run \`git rm -r --cached ${f.file || '<path>'}\` (stops tracking it; the file stays on your machine), add its folder to .gitignore, then \`git commit -m "stop tracking AI tool files"\`.`,
  },
  'test-registry-present': {
    title: 'Generated test logins exist on this machine',
    why: 'Your AI kept the logins it made for testing in .shipclear/test-accounts.json (git-ignored, so not in the repo). If any of them were ever added to a real database, they are working logins to your live app.',
    fix: 'Before launch: make sure none of these accounts exist in your production database, then delete .shipclear/test-accounts.json. Nothing to do in git — this is about your live app, not the code.',
  },
  'credential-in-use-is-public': {
    title: 'Your app is running on a credential anyone can look up',
    why: 'This is not a secret written in the wrong place — it is a secret that was never secret. A value copied from your own example file is published in your repo; a service\'s default password is in its documentation. Being "just the default" is the problem: defaults are the first thing anyone tries, by automated scanners, within hours of a domain going live.',
    fix: (f) => 'Generate a real value and use it in both places. To make one: `openssl rand -base64 36` (Mac/Linux) or, on any machine with Node, `node -e "console.log(require(\'crypto\').randomBytes(27).toString(\'base64\'))"`. Put it in `.env` only — never in the example file — and change it on the service itself too, or they will no longer match. Then stop it coming back: make the app refuse to start when the value is still a placeholder (a one-line check at startup), because that is what turns this from something to remember into something that cannot happen.'
      + containerDbNote(f),
  },
  'secret-default-fallback': {
    title: 'A missing secret quietly becomes a known one',
    why: 'If this variable is ever missing — a new server, a typo, a fresh deploy — your app will not fail. It will start up, use this fallback value instead, and look perfectly healthy. That value is written in your code for anyone to read, so the app ends up running on a password that is public, with nothing anywhere saying so.',
    fix: (f) => {
      // The reader's own variable name, not a placeholder — same rule as the
      // file-naming fix texts above.
      const k = f.key ? f.key.toUpperCase() : 'YOUR_VARIABLE';
      const lower = f.key || 'your_variable';
      return `Remove the fallback so a missing value fails loudly instead of quietly. In docker-compose, write \`\${${k}:?set ${k} in .env}\` — the \`:?\` makes the container refuse to start and print that message instead of booting on a known password. In code, read the variable with no default and raise if it is missing: \`os.environ["${k}"]\` in Python rather than \`os.getenv("${k}", "something")\`, or for a settings class \`${lower}: str\` with no \`= "..."\` after it; in JavaScript, \`if (!process.env.${k}) throw new Error("${k} is not set")\`. A crash on the first deploy is a good outcome here; a silent public password is not.`
        + containerDbNote(f);
    },
  },
  'public-bucket': {
    title: 'Anyone can read your uploaded files — and list them',
    why: 'This does not just let someone view one file if they already have the link. It lets anyone ask your storage for a list of every file in it, and then download them all. If your users upload anything personal — photos, screenshots, documents, invoices — it is public right now, and a listing is what turns "nobody knows the URL" into "here is the index".',
    fix: (f) => (f.listing
      ? 'Grant permission to read individual objects only, never to list the bucket. For MinIO, replace `mc anonymous set download` with an explicit policy that allows just `s3:GetObject` on `arn:aws:s3:::YOUR-BUCKET/*` and nothing on the bucket itself. For AWS S3, drop `s3:ListBucket` from the policy and turn the public-access block back on. Then check it rather than trusting the config: open your storage path in a browser (for example `https://yourapp.com/media/your-bucket/`) and confirm you do NOT get a list of files. Better still, serve user files through your own app so it can check who is asking.'
      : 'Confirm you meant this bucket to be world-readable. If it only holds things like public logos, that is fine — but add nothing else to it. If it holds anything a user uploaded, make it private and serve those files through your app, which can check who is asking. Verify by opening the bucket path in a browser window where you are not logged in.'),
  },
  'proxy-exposes-service': {
    title: 'A public web address forwards straight into a backing service',
    why: 'Everything that service answers is now reachable from the internet, not only the part you meant to share — its own status, admin and API endpoints come along with the route. If that service also uses a default password (very common for databases and storage in a docker-compose setup), it is fully exposed.',
    fix: (f) => `Narrow the route to the exact paths you need and reject everything else. For \`${f.route || 'that route'}\`, that means allowing only the specific path prefix your pages actually request, blocking the service's own API and admin paths, and allowing only \`GET\` and \`HEAD\` if it is just serving files. Check your work from outside: \`curl -i https://yourapp.com${f.route && f.route !== '/' ? f.route.replace(/[*]$/, '') : '/'}\` for something you expect to work, and a request for the service's own health or admin path to confirm it does not. If nothing in the browser needs this service directly, remove the public route altogether and have your app fetch from it internally.`,
  },
  'debug-route-public': {
    title: 'A debug or monitoring page is open to the public',
    why: 'These pages exist to tell you what your app is doing — request counts, internal paths, configuration, sometimes environment variables or a memory dump. Handed to a stranger, that is a map of your app and, at worst, your credentials.',
    fix: 'Either require authentication for this route, or make it exist only outside production. The pattern to copy is a conditional: define the route only when a production flag is off (in FastAPI, `docs_url="/api/docs" if not settings.is_production else None`; in Express, wrap the route in `if (process.env.NODE_ENV !== "production")`). If you need metrics in production, put them behind a login or restrict them to your own network at the proxy. Then confirm with `curl -i https://yourapp.com/<the path above>` — a 401, 403 or 404 is what you want to see.',
  },
  'headers-html-uncovered': {
    // Covers both shapes this finding takes: headers mounted on the API only,
    // and (when the probe checked the live root) none on the pages at all.
    title: 'Your safety headers do not cover the pages people load',
    why: 'These headers protect the pages people load in a browser — they tell the browser what the page is allowed to run. Setting them on your API, which does not run scripts, protects nothing. This one is easy to believe you have handled, because the configuration genuinely exists.',
    fix: 'Set the headers on the responses that serve your pages, not only on the API: the frontend service, the catch-all proxy route, or your framework\'s middleware for all paths. Then verify from outside rather than from the config: run `curl -I https://yourapp.com/` and check that `content-security-policy` is actually listed in the output (also worth seeing there: `strict-transport-security`, `x-frame-options`, `x-content-type-options`).',
  },
  'ssrf-unchecked-fetch': {
    title: 'Your server will fetch any web address a user gives it',
    why: 'Your server sits inside your private network, so "fetch this address" also means your database, your file storage, your admin pages — and on a cloud server, the internal address that hands out your cloud credentials. Whatever comes back can end up in whatever the feature shows the user. This is the usual cost of an import-from-URL, link-preview, avatar-from-URL or webhook feature.',
    fix: 'Before fetching, resolve the address and refuse anything that is not a public internet address. In Python: `ipaddress.ip_address(socket.gethostbyname(host)).is_global` must be true. In Node: resolve with `dns.promises.lookup(host)` and reject private ranges (`10.`, `172.16–31.`, `192.168.`, `127.`, `169.254.`) plus `::1` and `fc00::/7`. Then do the same check again after every redirect, and cap how many you follow (`follow_redirects=False` and handling them yourself is the simplest safe version) — a URL check on its own is stepped around by a redirect, which is the part people miss. Allowing only a short list of domains you expect is even better when the feature can live with it.',
  },
  'env-example-missing': {
    title: 'No .env.example template exists',
    why: 'Not a leak — just a courtesy: a template tells collaborators (and AI agents) which settings exist without revealing any values.',
    fix: 'Copy .env to .env.example and delete all the values, keeping just the variable names — or run `shipclear ship` again without `--no-fix` and ShipClear will create it for you.',
  },
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_LABEL = {
  critical: '🛑 CRITICAL', high: '🔴 HIGH', medium: '🟠 MEDIUM', low: '🟡 LOW', info: 'ℹ️  INFO',
};

// What a CLEARED verdict does and does not cover. Printed under the headline
// because "cleared to ship" on its own invites the reading that the software
// has been judged secure, and this command judged one half of that: the half
// a pattern can see. The other half is the semantic checklist, which needs
// something able to read the code.
export const CLEARED_SCOPE = [
  'Nothing blocking in the automated checks that ran. Those cover what a pattern',
  'can see: secrets, git history, committed files, deploy config. They cannot see',
  'whether every route checks who you are, whether your database rules let anyone',
  'read anything, or whether a price is trusted from the browser.',
];

// The checks that need code understanding rather than pattern matching. One
// list, used by the markdown report and counted by the next-steps text, so
// the number is never written down twice.
export const SEMANTIC_CHECKS = [
  '**Hidden accounts:** no route, seed, or conditional grants access via a fixed credential or magic string — including ones the AI created during development.',
  '**Auth and ownership:** every endpoint either requires authentication or is intentionally public; every resource access verifies the resource belongs to the requester (an ID alone is never enough).',
  '**Database exposure:** no world-readable/world-writable rules (Firebase rules, Supabase RLS, etc.).',
  '**Client-side leakage:** no server secret reaches anything delivered to the browser.',
  '**Input handling:** database/shell input parameterized, rendered HTML escaped, file uploads validated with size limits.',
  '**Server-side trust:** prices, roles, and privileged fields computed or verified server-side; webhook signatures verified before processing.',
  '**Session and abuse surface:** tokens in httpOnly cookies (not localStorage); rate limiting on login/signup/reset.',
  '**Debug surface:** no debug endpoints, stack traces shown to users, or `*` CORS on authenticated APIs.',
  '**AI surface** (if the app calls LLMs/agents): prompt inputs treated as untrusted, model output validated before executing/rendering/storing, agent and MCP tools least-privilege.',
  "**Credentials actually in use:** every password, key and token in the live config differs from the value in the example/sample config and from the service's documented default; the app refuses to start in production if a placeholder remains.",
  '**File and object storage:** no bucket or container is publicly readable, and nothing anonymous can **list** its contents. Confirm with a request to the bucket root, not just by reading config.',
  '**Proxy and ingress:** no public route forwards wholesale into a backing service (database, object store, queue, admin UI); routes are narrowed to the paths actually needed.',
  '**Outbound fetches:** if the server fetches URLs supplied by users (import-from-URL, link previews, webhooks, avatars), internal and cloud-metadata addresses are refused — and re-checked after every redirect.',
  '**Header coverage:** security headers apply to the responses that serve HTML, not only to the API.',
  '**Verdict update:** append any semantic findings here and restate the verdict (a critical one means DO NOT SHIP).',
];

// The guardrail lives *inside* the quoted prompt, not above it. People copy
// the quoted text and nothing else, and the prompt may well be pasted into a
// chat that never saw ShipClear's adapter rules — so the instruction not to
// rewrite history has to travel with it. An agent let loose on a
// secret-in-history finding can otherwise force-push a rewritten branch.
const AGENT_PROMPT = [
  '"Read SHIP-REPORT.md in this project and fix every finding, the critical',
  " ones first. Don't rewrite git history, and don't run any shipclear command",
  ' with --fix-history or --probe — tell me if a finding needs one and I\'ll',
  ' run it myself."',
];

/** Verdict-conditional closing guidance. Plain steps, in the order to do them. */
export function nextSteps(verdict, { quick = false } = {}) {
  const lines = ['  What to do next'];
  if (quick) {
    lines.push('   1. This was the quick check. Run the full gate before you ship: shipclear ship');
    lines.push('   2. Fix anything it reports, then run it again until the verdict changes.');
    return lines;
  }
  if (verdict === 'CLEARED') {
    lines.push(`   1. ${SEMANTIC_CHECKS.length} checks are still outstanding — the ones that need something able`);
    lines.push('      to read your code. They are listed at the end of SHIP-REPORT.md. Ask your');
    lines.push('      AI assistant to work through them, or a developer friend. No AI at all?');
    lines.push('      Paste that list and your code into any free AI chat.');
    lines.push(`   2. Put an honest badge in your README: ${BADGE_NEXT_STEP}`);
    lines.push('      (It re-runs this gate on GitHub for every push, so it turns red if a');
    lines.push('       commit lands that ShipClear would not clear.)');
    lines.push('   3. Run this again before every launch. A verdict describes the code as it is');
    lines.push('      right now, not as it will be after your next change.');
    return lines;
  }
  let n = 1;
  if (verdict === 'DO_NOT_SHIP') {
    lines.push(`   ${n++}. Rotate the keys listed above — now, before anything else. That is the step`);
    lines.push('      that actually protects you; the rest is cleanup.');
  }
  lines.push(`   ${n++}. Fix the findings. If you built this with an AI, paste it this:`);
  for (const l of AGENT_PROMPT) lines.push(`        ${l}`);
  lines.push(`   ${n++}. Run \`shipclear ship\` again, and keep going until the verdict changes.`);
  lines.push('   Stuck on any of it? Plain-English help:');
  lines.push('   https://github.com/adamtimmerberg/ShipClear/blob/main/docs/troubleshooting.md');
  return lines;
}

// Printed on every verdict, good news included. A limitation that only shows
// up alongside bad news is not a limitation anyone reads.
export const DISCLAIMER = [
  'ShipClear runs a limited set of automated checks. It is a supplement to',
  'security review, not a substitute for one, and a clear verdict is not a',
  'guarantee that your software is secure.',
];

export const DISCLAIMER_PARAGRAPH =
  'This report was produced by an automated tool. ShipClear runs a limited set of automated checks and cannot identify every security issue. A "cleared to ship" verdict means only that the checks listed in this report found nothing blocking — it is not a penetration test, not a code audit, and not a substitute for review by a qualified security professional. ShipClear is intended to supplement the work of a security team, not to replace it. You remain responsible for the security of the software you ship.';

const MARKER = { passed: ['[✓]', '32'], findings: ['[✗]', '31'], skipped: ['[–]', '33'] };

/**
 * One progress line, printed by the CLI as each check finishes. Green ran and
 * found nothing, red ran and found something, yellow did not run — a check
 * that found something is a check doing its job, which is why the red one is
 * not called a failure anywhere in the text.
 */
export function checkLine({ label, status, count }) {
  const [mark, code] = MARKER[status];
  const tail = status === 'findings' ? ` — ${count} to look at` : '';
  return `  ${color(code, mark)} ${label}${tail}`;
}

/** `23 of 25 checks ran · 2 skipped`, counted from the registry's own results. */
export function tallyLine(checks) {
  const skipped = checks.filter((c) => c.status === 'skipped').length;
  const ran = checks.length - skipped;
  return `  ${ran} of ${checks.length} checks ran`
    + (skipped ? ` · ${skipped} skipped` : '');
}

/** Soft-wrap prose to a terminal width, with a hanging indent for the rest. */
function wrap(text, { width = 78, first = '', rest = '' } = {}) {
  const out = [];
  let line = null;
  for (const word of text.split(/\s+/)) {
    if (line === null) { line = first + word; continue; }
    if (`${line} ${word}`.length > width) { out.push(line); line = rest + word; }
    else line = `${line} ${word}`;
  }
  if (line) out.push(line);
  return out;
}

/** Skipped checks keyed by the reason they share, in registry order. */
function groupByReason(skipped) {
  const groups = new Map();
  for (const c of skipped) {
    if (!groups.has(c.reason)) groups.set(c.reason, []);
    groups.get(c.reason).push(c.label);
  }
  return groups;
}

/**
 * The skipped checks, restated next to the verdict. Deliberately a repeat of
 * what scrolled past during the run: on a repo with findings the top of that
 * list is off-screen by the time the verdict lands, and "these were not
 * checked" is exactly the thing a reader must weigh the verdict against.
 */
export function skippedSection(checks) {
  const skipped = checks.filter((c) => c.status === 'skipped');
  if (!skipped.length) return [];
  const lines = ['  Not checked here:'];
  // Checks skipped for the same reason are grouped. A quick scan leaves most
  // of the registry unrun for one reason, and eighteen copies of the same
  // sentence is how a reader learns to skip this section entirely.
  for (const [reason, labels] of groupByReason(skipped)) {
    if (labels.length > 2) {
      lines.push(...wrap(`${labels.length} checks — ${reason}`, { first: '   – ', rest: '     ' }));
      lines.push(...wrap(labels.join(' · '), { first: '     ', rest: '     ' }));
    } else {
      for (const label of labels) lines.push(...wrap(`${label}: ${reason}`, { first: '   – ', rest: '     ' }));
    }
  }
  return lines;
}

export function verdictOf(findings) {
  const open = findings.filter((f) => !f.resolved);
  if (open.some((f) => f.severity === 'critical')) return 'DO_NOT_SHIP';
  if (open.some((f) => f.severity === 'high' || f.severity === 'medium')) return 'SHIP_WITH_FIXES';
  return 'CLEARED';
}

export const VERDICT_TEXT = {
  DO_NOT_SHIP: '🛑 DO NOT SHIP — fix the critical findings first.',
  SHIP_WITH_FIXES: '🟡 SHIP WITH FIXES — nothing catastrophic, but close the items listed above first.',
  CLEARED: '✅ CLEARED TO SHIP — with work still to do',
};

// `scan` deliberately skips slower checks (full git history, dependency
// audits — see checks.js's `quick` mode) so it can run instantly. Its
// verdict must never be visually or textually confusable with the real
// ship/no-ship call from the full gate — a quick scan saying "CLEARED TO
// SHIP" is exactly the false-GO failure mode this project treats as its
// worst case (see CONTRIBUTING.md). Found by an independent fresh-eyes
// test that ran `scan`, saw this exact banner, and nearly stopped there.
const QUICK_VERDICT_TEXT = {
  DO_NOT_SHIP: '🛑 Secrets found in this quick check — do not ship yet.',
  SHIP_WITH_FIXES: '🟡 Issues found in this quick check.',
  CLEARED: '✅ No secrets found in this quick check — but this is NOT the full gate (it looks at your current files only, not git history or dependencies).',
};

// Deliberately not a badge image. A static green "cleared to ship" picture
// keeps making that claim on every later commit, checked or not — a false
// GO, handed out by the tool whose whole job is preventing them. The real
// badge is a live GitHub Actions status installed by `shipclear badge`,
// which re-runs this gate on GitHub for every push (see lib/badge.js).
export const BADGE_NEXT_STEP = 'shipclear badge';

function sorted(findings) {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
      || (a.file || '').localeCompare(b.file || '')
      || (a.line || 0) - (b.line || 0)
  );
}

function location(f) {
  if (!f.file) return '';
  return f.line ? `${f.file}:${f.line}` : f.file;
}

const color = (code, s) =>
  process.stdout.isTTY && !process.env.NO_COLOR ? `\x1b[${code}m${s}\x1b[0m` : s;

// Fix texts are either a plain string or a function of the finding (see
// EXPLAIN above) — so the reader gets real file names and repo-specific
// steps, never a `<file>` placeholder.
const fixTextFor = (ex, f) => (typeof ex.fix === 'function' ? ex.fix(f) : ex.fix);

/**
 * The line the run opens with. The version is read from package.json by the
 * CLI and passed in, so the banner can never claim a version that isn't the
 * one running.
 */
export function banner(version, { quick = false } = {}) {
  return `\n  ShipClear v${version} — ${quick ? 'quick scan' : 'ship report'}`
    + '\n  MIT · runs on your machine · nothing is uploaded\n\n';
}

/**
 * Everything after the progress lines: findings, the tally, the verdict, what
 * was not checked, what to do next, and the disclaimer.
 *
 * Pure — it returns a string and prints nothing, so the live progress lines
 * (which the CLI prints through runGate's onCheck as each check finishes)
 * stay out of it and the whole report body remains testable in one call.
 */
export function renderTerminal({ findings, notes, verdict, fixes = [], version, quick = false, checks = [] }) {
  const lines = [];
  lines.push('');

  const open = sorted(findings.filter((f) => !f.resolved));
  for (const f of open) {
    const ex = EXPLAIN[f.id];
    lines.push(`  ${SEVERITY_LABEL[f.severity]}  ${ex.title}`);
    if (location(f)) lines.push(`      where: ${location(f)}${f.detail ? ` — ${f.detail}` : ''}`);
    else if (f.detail) lines.push(`      ${f.detail}`);
    lines.push(`      why it matters: ${ex.why}`);
    // Fix text may be multi-line (numbered steps for the involved fixes);
    // keep the "what to do:" label on the first line and indent the rest so
    // steps read as a list, not a wall of prose.
    const fixLines = fixTextFor(ex, f).split('\n');
    lines.push(`      what to do: ${fixLines[0]}`);
    for (const extra of fixLines.slice(1)) lines.push(`                  ${extra}`);
    lines.push('');
  }
  if (open.length === 0) lines.push('  No findings. Nice.');
  if (fixes.length) {
    lines.push('');
    lines.push('  Fixed for you:');
    for (const fix of fixes) lines.push(`   ✔ ${fix}`);
  }
  for (const note of notes) lines.push(`  note: ${note}`);

  // The findings loop already ends on a blank line; don't stack a second one.
  if (lines[lines.length - 1] !== '') lines.push('');
  if (checks.length) lines.push(tallyLine(checks));
  const v = quick ? QUICK_VERDICT_TEXT[verdict] : VERDICT_TEXT[verdict];
  lines.push('  ' + color(verdict === 'CLEARED' ? '32;1' : verdict === 'DO_NOT_SHIP' ? '31;1' : '33;1', v));
  // Only the full gate earns the scoped-clear wording; the quick scan's own
  // verdict text already says it is not the gate.
  if (verdict === 'CLEARED' && !quick) for (const l of CLEARED_SCOPE) lines.push(`     ${l}`);

  const skipped = skippedSection(checks);
  if (skipped.length) {
    lines.push('');
    lines.push(...skipped);
  }

  lines.push('');
  lines.push(...nextSteps(verdict, { quick }));

  lines.push('');
  lines.push(quick ? '  This was a quick check only. For the full gate: shipclear ship' : '  Full report written to SHIP-REPORT.md');
  lines.push('');
  for (const l of DISCLAIMER) lines.push(`  ${l}`);
  lines.push('');
  return lines.join('\n');
}

export function renderMarkdown({ findings, notes, verdict, fixes = [], version, semanticSection = true, checks = [] }) {
  const open = sorted(findings.filter((f) => !f.resolved));
  const out = [];
  out.push('# Ship Report');
  out.push('');
  out.push(`> Generated by [ShipClear](https://github.com/adamtimmerberg/ShipClear) v${version} on ${new Date().toISOString().slice(0, 10)}`);
  out.push('');
  out.push(`## Verdict: ${VERDICT_TEXT[verdict]}`);
  out.push('');
  if (verdict === 'CLEARED') {
    out.push(CLEARED_SCOPE.join(' '));
    out.push('');
  }
  if (checks.length) {
    const skipped = checks.filter((c) => c.status === 'skipped');
    out.push(`**${checks.length - skipped.length} of ${checks.length} checks ran**`
      + (skipped.length ? ` · ${skipped.length} skipped` : ''));
    out.push('');
    out.push('| | Check | Result |');
    out.push('|---|---|---|');
    for (const c of checks) {
      const mark = c.status === 'passed' ? '✓' : c.status === 'findings' ? '✗' : '–';
      const result = c.status === 'passed' ? 'nothing found'
        : c.status === 'findings' ? `${c.count} to look at`
        : 'not run';
      out.push(`| ${mark} | ${c.label} | ${result} |`);
    }
    out.push('');
    if (skipped.length) {
      out.push('### Not checked here');
      out.push('');
      for (const [reason, labels] of groupByReason(skipped)) {
        out.push(labels.length > 2
          ? `- **${labels.length} checks** — ${reason}\n  - ${labels.join('\n  - ')}`
          : labels.map((l) => `- **${l}** — ${reason}`).join('\n'));
      }
      out.push('');
    }
  }
  if (verdict === 'CLEARED') {
    out.push('Cleared! To show this in your README, run:');
    out.push('');
    out.push('```bash');
    out.push(BADGE_NEXT_STEP);
    out.push('```');
    out.push('');
    out.push('That installs a badge backed by a GitHub Actions run of this same gate, so it reflects what is actually on GitHub — green while every pushed commit clears, red as soon as one does not, grey if nothing was checked.');
    out.push('');
  }
  if (open.length === 0) {
    out.push('No findings from the deterministic scan.');
  } else {
    out.push(`## Findings (${open.length})`);
    for (const f of open) {
      const ex = EXPLAIN[f.id];
      out.push('');
      out.push(`### ${SEVERITY_LABEL[f.severity]} — ${ex.title}`);
      if (location(f)) out.push(`- **Where:** \`${location(f)}\`${f.detail ? ` — ${f.detail}` : ''}`);
      else if (f.detail) out.push(`- **Detail:** ${f.detail}`);
      out.push(`- **Why it matters:** ${ex.why}`);
      // Multi-line fix text becomes a nested list so numbered steps render
      // as steps in the markdown report, not one run-on bullet.
      const fixLines = fixTextFor(ex, f).split('\n');
      if (fixLines.length === 1) {
        out.push(`- **What to do:** ${fixLines[0]}`);
      } else {
        out.push('- **What to do:**');
        for (const step of fixLines) out.push(`  - ${step}`);
      }
    }
  }
  if (fixes.length) {
    out.push('');
    out.push('## Fixed automatically');
    for (const fix of fixes) out.push(`- ✔ ${fix}`);
  }
  if (notes.length) {
    out.push('');
    out.push('## Notes');
    for (const note of notes) out.push(`- ${note}`);
  }
  if (semanticSection) {
    out.push('');
    out.push('## Semantic checks — for your AI assistant');
    out.push('');
    out.push('The scan above catches everything a pattern can catch. These need code understanding — ask your AI assistant to work through them (the ShipClear adapters do this automatically):');
    out.push('');
    for (const item of SEMANTIC_CHECKS) out.push(`- [ ] ${item}`);
    out.push('');
    out.push("Running ShipClear without an AI coding tool? Paste this checklist and your code into any AI chat (ChatGPT, Claude.ai, Gemini — even a free one) and ask it to work through the list — or ask a developer friend. These checks matter, but they need something that can read your code to answer them.");
  }
  out.push('');
  out.push('## What to do next');
  out.push('');
  // The terminal version is indented for a terminal; the report wants plain
  // markdown, so the same lines are stripped of their leading spaces.
  for (const line of nextSteps(verdict).slice(1)) out.push(line.replace(/^\s{3}/, '').trimEnd());
  out.push('');
  out.push('---');
  out.push('');
  out.push(DISCLAIMER_PARAGRAPH);
  out.push('');
  return out.join('\n');
}

export { EXPLAIN };
