// Detection patterns for the deterministic layer.
// Rule of the house: every pattern here must be proven by a fixture in
// tests/fixtures — both that it catches the real shape and that it stays
// quiet on placeholders.

// Passwords that make a connection string a template, not a leak. Tuned
// against real starter repos (t3, taxonomy, fastapi-template all ship URLs
// like mysql://root:password@localhost as documentation).
const TEMPLATE_DB_PASSWORDS = /^(?:(?:my|your)?pass(?:word)?|passw0rd|pwd|secret|changethis|changeme|change-me|root|postgres|mysql|mariadb|redis|mongo|admin|user|username|guest|test|dev|devel|local|localdev|example|sample|docker|1234\d{0,4})$/i;

function connectionStringHasRealPassword(match) {
  const beforeAt = match.slice(0, -1); // strip trailing '@'
  const password = beforeAt.slice(beforeAt.lastIndexOf(':') + 1);
  return !TEMPLATE_DB_PASSWORDS.test(password) && !looksPlaceholder(password);
}

function base64UrlDecode(s) {
  try {
    return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  } catch {
    return '';
  }
}

// JWTs are everywhere and mostly harmless (expired demos, public Supabase
// anon keys). The one that must never leak is a Supabase service-role key —
// identifiable by its payload. Everything else is deliberately ignored.
function isServiceRoleJwt(match) {
  return base64UrlDecode(match.split('.')[1]).includes('"role":"service_role"');
}

// A PEM header on its own is documentation — a line telling the reader where
// to paste their certificate, which is how our own docs describe setting one
// up. Key *material* is the header followed by its base64 body. Requiring the
// body is what keeps a shell comment from being reported as a leaked key, and
// (because history findings run through the same matcher) keeps a comment from
// ever recommending a force-push of rewritten history.
function privateKeyHasBody(match, content, index) {
  const after = (content || '').slice(index + match.length, index + match.length + 400);
  // Covers both real PEM files and one-line JSON/env embeddings, where the
  // body follows a literal \n escape rather than a newline.
  const body = after.replace(/\\n/g, '\n').match(/[A-Za-z0-9+/=]{40,}/);
  return !!body && entropy(body[0]) > 3.5;
}

// Provider-specific formats. These are high-confidence: a match is treated as
// a real secret even if it "looks fake", because a real-shaped key must be
// rotated anyway once it has touched a tracked file. A pattern may carry a
// `validate(match, content, index)` to veto matches that are provably
// templates.
export const SECRET_PATTERNS = [
  { id: 'aws-access-key', name: 'AWS access key', regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'anthropic-api-key', name: 'Anthropic API key', regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { id: 'stripe-live-key', name: 'Stripe live secret key', regex: /\bsk_live_[0-9a-zA-Z]{16,}\b/g },
  { id: 'stripe-test-key', name: 'Stripe test secret key', regex: /\bsk_test_[0-9a-zA-Z]{16,}\b/g, severity: 'medium' },
  { id: 'openrouter-api-key', name: 'OpenRouter API key', regex: /\bsk-or-v1-[a-f0-9]{64}\b/g },
  { id: 'openai-api-key', name: 'OpenAI API key', regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g },
  { id: 'github-token', name: 'GitHub token', regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
  { id: 'google-api-key', name: 'Google API key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'slack-token', name: 'Slack token', regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { id: 'sendgrid-api-key', name: 'SendGrid API key', regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { id: 'npm-token', name: 'npm access token', regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'huggingface-token', name: 'Hugging Face token', regex: /\bhf_[A-Za-z0-9]{34}\b/g },
  { id: 'digitalocean-token', name: 'DigitalOcean token', regex: /\bdop_v1_[a-f0-9]{64}\b/g },
  { id: 'groq-api-key', name: 'Groq API key', regex: /\bgsk_[A-Za-z0-9]{20,}\b/g },
  { id: 'xai-api-key', name: 'xAI API key', regex: /\bxai-[A-Za-z0-9]{20,}\b/g },
  { id: 'azure-account-key', name: 'Azure storage account key', regex: /AccountKey=[A-Za-z0-9+/=]{40,}/g },
  { id: 'supabase-service-role', name: 'Supabase service-role key (JWT)', regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, validate: isServiceRoleJwt },
  { id: 'private-key-block', name: 'Private key material', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/g, validate: privateKeyHasBody },
  { id: 'connection-string', name: 'Database URL with embedded password', regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^:/\s'"]+:[^@/\s'"]+@/g, validate: connectionStringHasRealPassword },
];

// Values that are clearly stand-ins, not real credentials. Only applied to
// generic matches and validate() hooks — never to raw provider formats.
// {{ }} covers mustache/jinja templates; env( covers config indirection
// (supabase config.toml); the all-caps test covers constant-style
// placeholders like API_KEY_HERE (all tuned on real starter repos).
const PLACEHOLDER = /xxx|\.\.\.|your[_-]?|example|sample|placeholder|change[_-]?me|dummy|fake[_-]|insert[_-]?|<[^>]*>|\$\{|\{\{|%s|\bTODO\b/i;

export function looksPlaceholder(value) {
  return (
    PLACEHOLDER.test(value) ||
    /^env\(/i.test(value) ||
    /^[A-Z0-9]+(?:_[A-Z0-9]+)+$/.test(value)
  );
}

export function entropy(s) {
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let h = 0;
  for (const c in freq) {
    const p = freq[c] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// Assignments of suspicious names to string literals, e.g. apiKey = "...".
const GENERIC_ASSIGNMENT = /\b(api[_-]?key|apikey|secret[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token|token)\b\s*[:=]\s*['"`]([^'"`\n]{8,})['"`]/gi;

export function maskSecret(value) {
  return value.length <= 8 ? value[0] + '…' : value.slice(0, 8) + '…';
}

export function lineOfIndex(content, index) {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

/**
 * Scan a string for secrets. Returns matches with pattern metadata, ordered
 * by position. Overlapping matches are deduplicated in favor of the more
 * specific pattern (SECRET_PATTERNS order, generics last).
 */
// In a documentation file, a key block wrapped in instructions is a worked
// example, not a leak — "paste your key here", "this file is .gitignored".
// Outside docs this never applies: a real key pasted into code is a real key.
const INSTRUCTIONAL = /\.gitignore|paste|example|sample|placeholder|replace|your own|looks like/i;

function isWorkedExample(content, index) {
  return INSTRUCTIONAL.test(content.slice(Math.max(0, index - 300), index + 300));
}

export function findSecrets(content, { includeGeneric = true, docFile = false } = {}) {
  const raw = [];
  for (const p of SECRET_PATTERNS) {
    p.regex.lastIndex = 0;
    let m;
    while ((m = p.regex.exec(content))) {
      if (p.validate && !p.validate(m[0], content, m.index)) continue;
      raw.push({
        patternId: p.id,
        name: p.name,
        index: m.index,
        match: m[0],
        severity: p.severity || 'critical',
      });
    }
  }
  if (includeGeneric) {
    GENERIC_ASSIGNMENT.lastIndex = 0;
    let m;
    while ((m = GENERIC_ASSIGNMENT.exec(content))) {
      const value = m[2];
      if (looksPlaceholder(value)) continue;
      // Low-entropy, digit-free values ("mysecretvalue") are usually stubs.
      if (entropy(value) < 3 && !/\d/.test(value)) continue;
      raw.push({
        patternId: 'generic-secret',
        name: `Hardcoded ${m[1]}`,
        index: m.index,
        match: m[0],
        value,
        severity: 'medium',
      });
    }
  }
  const candidates = docFile
    ? raw.filter((h) => !(h.patternId === 'private-key-block' && isWorkedExample(content, h.index)))
    : raw;
  const kept = [];
  for (const cand of candidates) {
    const overlaps = kept.some(
      (k) => cand.index < k.index + k.match.length && k.index < cand.index + cand.match.length
    );
    if (!overlaps) kept.push(cand);
  }
  return kept.sort((a, b) => a.index - b.index);
}

// --- PII patterns (used only on data files) ---

export const EMAIL = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
export const SSN = /\b\d{3}-\d{2}-\d{4}\b/g;

const FAKE_EMAIL_DOMAINS = /@(example\.(?:com|org|net)|test\.com|email\.com|domain\.com|yourdomain\.|acme\.|localhost)/i;

export function realLookingEmails(content) {
  EMAIL.lastIndex = 0;
  const seen = new Set();
  let m;
  while ((m = EMAIL.exec(content))) {
    if (!FAKE_EMAIL_DOMAINS.test(m[0])) seen.add(m[0].toLowerCase());
  }
  return [...seen];
}

// --- misc shared patterns ---

// Password-ish identifier assigned a short string literal. Deliberately no
// leading \b: it must also hit inside names like TEST_PASSWORD. The optional
// quote before the separator covers JSON and quoted-key object literals
// (`"password": "…"`), the shape an AI writes into a seed or fixture file.
// Matches password-ish identifiers: password / passwd / pass, plus the short
// forms pwd / pword an AI sometimes uses (found missed on a monorepo test).
// No leading \b, so it also fires inside names like TEST_PASSWORD; the
// two-signal test-account rule (a suspicious account email nearby) keeps the
// broader match from producing false findings on its own.
// The optional env-fallback group covers `ADMIN_PASSWORD = process.env.X ||
// "literal"` / `?? "literal"` — found missed on a real AI-generated app: an
// otherwise reasonable-looking "overridable via env" default that still
// ships a real hardcoded password when no env var is set.
export const PASSWORD_ASSIGNMENT = /(?:pass(?:word|wd)?|pword|pwd)[a-z0-9_]*["']?\s*[:=]\s*(?:process\.env\.[A-Z0-9_]+\s*(?:\|\||\?\?)\s*)?['"][^'"\n]{4,}['"]/i;

// Quoted email that smells like a built-in account, OR a bare privileged
// username/role literal (admin, root, superuser, test, demo) assigned,
// directly or via the same env-fallback idiom, to an identifier that reads
// as an account holder (user/username/login/account/email). The bare-
// username branch exists because `ADMIN_USER = process.env.ADMIN_USER ||
// "admin"` — no email in sight — is at least as common in real AI-written
// "quick gate for now" code as an admin@... literal, and the original
// email-only form missed it entirely on a real generated app.
export const SUSPICIOUS_ACCOUNT_EMAIL = /['"][a-z0-9._%+-]*(?:admin|test|demo|root|superuser)[a-z0-9._%+-]*@[a-z0-9.-]+\.[a-z]{2,}['"]|(?:user|username|login|account|email)[a-z0-9_]*["']?\s*[:=]\s*(?:process\.env\.[A-Z0-9_]+\s*(?:\|\||\?\?)\s*)?['"](?:admin|test|demo|root|superuser)['"]/i;

// Turning off TLS certificate checking — the "fix" an AI assistant reaches
// for when a request fails with a certificate error. Deterministic and
// high-confidence: there is no placeholder form of the disable-verification
// flag. (Examples live in tests/fixtures, not here — the gate scans this
// file, and a real matchable form in a comment would flag our own repo.)
export const TLS_VERIFICATION_OFF = /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|\bverify\s*=\s*False\b/g;

// The leading lookbehind requires an absolute-path boundary, so a real home
// path matches but the `/home/` inside an import like `components/home/card`
// does not (found the hard way on the precedent starter repo).
// Flask/Werkzeug debug mode left on in code that ships. Scoped to the
// genuinely dangerous form — a Flask app.run call with debug enabled, or the
// FLASK_DEBUG env flag — not Django's dev-default DEBUG setting, which would
// drown users in false positives. Debug mode exposes an interactive Python
// console to anyone who triggers an error: remote code execution. (Examples
// live in tests, worded so they don't match this scanned file.)
export const DEBUG_MODE_ON = /\.run\([^)]*\bdebug\s*=\s*True|FLASK_DEBUG\s*[:=]\s*['"]?1\b|FLASK_ENV\s*[:=]\s*['"]?development\b/g;

export const PERSONAL_PATH = /(?<![\w./-])(?:\/(?:home|Users)\/[A-Za-z0-9._-]{3,}|[A-Z]:\\Users\\[A-Za-z0-9._-]{3,})/g;

const IMPERSONAL_PATH_USERS = new Set([
  'user', 'username', 'yourname', 'your-name', 'example', 'runner', 'node',
  'app', 'ubuntu', 'ec2-user', 'root', 'admin', 'test', 'you', 'name',
]);

export function personalPaths(content) {
  PERSONAL_PATH.lastIndex = 0;
  const hits = [];
  let m;
  while ((m = PERSONAL_PATH.exec(content))) {
    const user = m[0].split(/[/\\]/).filter(Boolean).pop().toLowerCase();
    if (!IMPERSONAL_PATH_USERS.has(user)) hits.push({ index: m.index, match: m[0] });
  }
  return hits;
}

// ===========================================================================
// Deployment configuration patterns.
//
// Everything below answers a different question from the patterns above. Those
// ask "is there a secret written here that shouldn't be?"; these ask "is the
// value this app actually runs on one that anybody can look up?" — the live
// config, the fallback it silently uses when a variable is missing, and the
// places a deployment hands a backing service straight to the internet.
// Used by lib/infra.js.
// ===========================================================================

// Keys whose *value* is a credential. Compound forms only, with one
// exception: a bare all-caps `KEY`. A lowercase `key:` is ordinary YAML
// (`- key: tls.crt`), where testing the value would misfire.
const SECRET_KEY_NAME = /pass(?:word|wd)?|pword|pwd|secret|token|credential|private|_key$|^api[_-]?key$|^access[_-]?key$/i;
// Names that match the above but are public by design, or hold something
// that isn't the credential itself (a path, a length, an algorithm).
const NOT_SECRET_KEY_NAME = /^(?:NEXT_PUBLIC|VITE|REACT_APP|NUXT_PUBLIC|EXPO_PUBLIC|PUBLIC)_|(?:PUBLIC|PUBLISHABLE|ANON|SITE)_KEY$|_KEY_(?:FILE|PATH|ID)$|_KEYFILE$|_(?:URL|URI|HOST|PORT|ID|NAME|USER|USERNAME|ALGORITHM|ALGO|LENGTH|SIZE|EXPIRE|EXPIRES|EXPIRY|TTL|DAYS|HOURS|MINUTES|SECONDS|ROUNDS|ENABLED|REQUIRED|PROVIDER|TYPE|REGION|BUCKET|ISSUER|AUDIENCE|HEADER|COOKIE|PREFIX|VERSION|PATH|DIR|DIRECTORY|FILE|FILENAME|IMAGE|TAG|EMAIL|DOMAIN|LOCALE|TIMEZONE|TZ|MODE|LEVEL|FORMAT|MODEL|ENDPOINT|CHANNEL|TOPIC|QUEUE|TABLE|SCHEMA|DATABASE|DB|INDEX|LIMIT|MAX|MIN|COUNT|TIMEOUT|INTERVAL|RETRIES)$/i;

export function isSecretishKey(key) {
  if (NOT_SECRET_KEY_NAME.test(key)) return false;
  return key === 'KEY' || SECRET_KEY_NAME.test(key);
}

// Credentials that ship as the documented default of a service, or that
// every tutorial for it uses. An attacker's first guess, by definition.
const KNOWN_DEFAULT_CREDENTIALS = new Set([
  'minioadmin', 'postgres', 'mysql', 'mariadb', 'mongo', 'mongodb', 'redis',
  'elastic', 'elasticsearch', 'rabbitmq', 'neo4j', 'keycloak', 'grafana',
  'root', 'toor', 'admin', 'administrator', 'guest', 'user', 'test', 'dev', 'docker',
  'password', 'passwd', 'pass', 'secret', 'changeme', 'change-me', 'change_me',
  'letmein', 'supersecret', 'mysecret', 'mysecretpassword',
  '1234', '12345', '123456', 'password123', 'admin123',
]);
// Not a service's default — a stand-in the project itself shipped and nobody
// replaced. Just as guessable, but it reads differently in a finding.
const LEFTOVER_STAND_IN = /^(?:change[-_]?me|changethis|django-insecure-|your[-_]|insecure|dev[-_]?only|test[-_]?pass|replace[-_]?me)/i;

export function isKnownDefaultCredential(value) {
  return KNOWN_DEFAULT_CREDENTIALS.has(value.toLowerCase());
}

export function isLeftoverStandIn(value) {
  return LEFTOVER_STAND_IN.test(value);
}

// `${FOO}` / `$FOO` is indirection, not a value — whatever it resolves to
// isn't visible here, so it can't be judged (check #2 handles the form that
// carries a default).
export function isVariableReference(value) {
  return /^\$\{[^}]*\}$/.test(value) || /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(value);
}

const PLACEHOLDER_VALUE = /change|example|sample|dev[-_]?only|todo|xxx|placeholder|dummy|fake|replace|your[-_]|[-_]here$/i;

/** A value that is visibly a stand-in rather than a generated credential. */
export function placeholderShapedCredential(key, value) {
  if (/^<.*>$/.test(value) || /^__.*__$/.test(value)) return true;
  if (PLACEHOLDER_VALUE.test(value)) return true;
  // A key, token or signing secret is generated and long. A short one was
  // typed by a human, which means it is guessable. (Passwords are excluded:
  // plenty of real ones are short, and the lists above already cover the
  // guessable ones.)
  return /secret|token|_key$|^key$|api[_-]?key/i.test(key) && value.length < 12 && !/^[\d.]+$/.test(value);
}

// Signals that this config describes something the public can reach, which is
// what turns a known credential from untidy into urgent.
const PRODUCTION_FLAG = /\b(?:ENVIRONMENT|APP_ENV|NODE_ENV|FLASK_ENV|RAILS_ENV|DJANGO_ENV|ENV)\s*[:=]\s*["']?prod(?:uction)?\b|\b(?:SESSION_)?COOKIE_SECURE\s*[:=]\s*["']?[Tt]rue\b/;
const DOMAIN_SETTING = /(?:BASE_URL|SITE_URL|PUBLIC_URL|FRONTEND_URL|BACKEND_URL|API_URL|ALLOWED_HOSTS|ALLOWED_ORIGINS|CORS_ORIGINS|SERVER_NAME|host)\s*[:=]\s*["']?(?:https?:\/\/)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})/gi;
const NON_PUBLIC_HOST = /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|.+\.(?:local|localhost|test|internal|example\.com|docker\.internal|svc\.cluster\.local))$/i;

/** The production signal this text carries, as a quotable phrase, or null. */
export function productionSignal(text) {
  const flag = text.match(PRODUCTION_FLAG);
  if (flag) return `\`${flag[0].trim()}\``;
  DOMAIN_SETTING.lastIndex = 0;
  let m;
  while ((m = DOMAIN_SETTING.exec(text))) {
    if (!NON_PUBLIC_HOST.test(m[1])) return `the public address \`${m[1]}\``;
  }
  return null;
}

// --- #2: a missing secret that silently becomes a known one ---

// Shell/compose default expansion: ${FOO:-default}, ${FOO-default}.
export const SHELL_DEFAULT = /\$\{([A-Za-z_][A-Za-z0-9_]*)\s*:?-\s*([^}\n]*)\}/g;

// Code-level "work even if it isn't configured" defaults. Each returns the
// variable name in group 1 and the default value in group 2.
export const CODE_DEFAULTS = [
  // Python: os.getenv("X", "default") / os.environ.get("X", "default")
  /(?:os\.)?(?:getenv|environ\.get)\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,\s*['"]([^'"\n]+)['"]/g,
  // JS/TS: process.env.X || "default" / process.env["X"] ?? "default"
  /process\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[['"]([A-Za-z_][A-Za-z0-9_]*)['"]\])\s*(?:\|\||\?\?)\s*['"]([^'"\n]+)['"]/g,
  // Ruby: ENV.fetch("X", "default") / ENV["X"] || "default"
  /ENV(?:\.fetch\(|\[)\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*(?:,|\]\s*\|\|)\s*['"]([^'"\n]+)['"]/g,
  // Go: flag.String("x", "default", ...) / os.Getenv fallbacks
  /flag\.String\(\s*"([A-Za-z_][A-Za-z0-9_.-]*)"\s*,\s*"([^"\n]+)"/g,
  // Settings classes (pydantic, dataclasses): secret_key: str = "default"
  /^[ \t]+([a-z_][a-z0-9_]*)\s*:\s*[A-Za-z_][A-Za-z0-9_.\[\]]*\s*=\s*['"]([^'"\n]+)['"]/gm,
];

// --- #3: storage anyone can read, or list ---

// `mc anonymous set download` is the trap: despite the name it is not
// read-only-per-object, it grants s3:ListBucket too.
// The trailing `alias/bucket` is required, not decoration: a real invocation
// always names a target, and demanding one is what keeps prose *about* this
// command — our own fix text included — from being read as the command.
export const MC_ANONYMOUS = /\bmc\s+(?:--\S+\s+)*(?:anonymous|policy)\s+set(?:-json)?\s+(download|upload|public|write|none)\s+(\S+\/\S+)/g;
export const AWS_PUBLIC_ACL = /--acl[= ]\s*(public-read-write|public-read)\b/g;
export const TF_PUBLIC_ACL = /\bacl\s*=\s*"(public-read-write|public-read)"/g;
export const TF_PUBLIC_ACCESS_BLOCK_OFF = /\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b/g;
export const WILDCARD_PRINCIPAL = /"Principal"\s*:\s*(?:"\*"|\{[^}]*"AWS"\s*:\s*(?:\[\s*)?"\*")/g;
export const S3_ACTION = /"(s3:[A-Za-z*]+)"/g;
export const GCS_ALL_USERS = /["'](allUsers|allAuthenticatedUsers)["']/g;
export const AZURE_PUBLIC_CONTAINER = /(?:public_access|container_access_type)\s*=\s*"(container|blob)"/gi;
export const FIREBASE_OPEN_RULE = /allow\s+([a-z, ]+)\s*:\s*if\s+true\b/g;

// --- #4: a public route that forwards into a backing service ---

export const PROXY_UPSTREAM_LINE = /reverse_proxy|proxy_pass|ProxyPass|^\s*server\s+\S+:\d+|loadBalancer|load_balancer|serviceName|service_name|^\s*(?:name|number|port):/;
export const PROXY_ROUTE_LINE = /^\s*(?:handle_path|handle|route|location|path|ProxyPass)\s+([^\s{]+)|^\s*-\s*path:\s*(\S+)/;
export const HOST_PORT = /\b([a-z0-9][a-z0-9_.-]*):(\d{2,5})\b/gi;

// Backing services that should never answer the internet wholesale. Value is
// the severity: a database or admin UI is worse than an object store, which
// at least is partly meant to serve files.
export const BACKING_SERVICES = {
  postgres: 'critical', postgresql: 'critical', mysql: 'critical', mariadb: 'critical',
  mongo: 'critical', mongodb: 'critical', redis: 'critical', valkey: 'critical',
  elasticsearch: 'critical', opensearch: 'critical', clickhouse: 'critical',
  couchdb: 'critical', neo4j: 'critical', cassandra: 'critical', memcached: 'critical',
  rabbitmq: 'critical', kafka: 'critical', nats: 'critical',
  consul: 'critical', vault: 'critical', etcd: 'critical',
  adminer: 'critical', pgadmin: 'critical', phpmyadmin: 'critical', mailhog: 'critical',
  kibana: 'critical', grafana: 'critical', prometheus: 'critical',
  minio: 'high', s3: 'high', seaweedfs: 'high', garage: 'high',
};

export const BACKING_PORTS = {
  5432: 'postgres', 3306: 'mysql', 27017: 'mongodb', 6379: 'redis',
  9200: 'elasticsearch', 9300: 'elasticsearch', 5601: 'kibana', 8123: 'clickhouse',
  5984: 'couchdb', 7474: 'neo4j', 7687: 'neo4j', 11211: 'memcached',
  15672: 'rabbitmq', 5672: 'rabbitmq', 9092: 'kafka', 8500: 'consul', 8200: 'vault',
  9090: 'prometheus', 3000: null, 9000: null, 9001: null,
};

// --- #5: debug and monitoring pages open to the public ---

// Paths that answer with the internals of a running app. The value is the
// severity: most are an information leak, a few hand over the environment.
export const SENSITIVE_PATHS = {
  '/metrics': 'medium', '/debug': 'medium', '/debug/pprof': 'critical',
  '/actuator': 'medium', '/actuator/env': 'critical', '/actuator/heapdump': 'critical',
  '/server-status': 'medium', '/swagger': 'medium', '/swagger-ui': 'medium',
  '/api/docs': 'medium', '/api/redoc': 'medium', '/openapi.json': 'medium',
  '/graphql': 'medium', '/adminer': 'critical', '/pgadmin': 'critical',
  '/.env': 'critical', '/phpinfo.php': 'critical',
};

export const ROUTE_DEFINITION = /@(?:app|router|bp|blueprint)\.(?:get|post|route)\(\s*['"]([^'"]+)['"]|\b(?:app|router|server|api)\.(?:get|use|all)\(\s*['"]([^'"]+)['"]|HandleFunc\(\s*"([^"]+)"|(?:docs_url|redoc_url|openapi_url|metrics_path)\s*=\s*['"]([^'"]+)['"]/g;

// Signals that a route is already protected, or only exists outside
// production. The second kind matters as much as the first: a docs route
// written as `docs_url="/api/docs" if not settings.is_production else None`
// is the *correct* pattern and must not be reported.
export const AUTH_NEARBY = /Depends\(|Security\(|login_required|require(?:s)?_?(?:auth|login|admin)|authenticate|authorized|IsAuthenticated|permission_classes|basic_?auth|api_?key|@auth|ensureAuth|ensureLoggedIn|requireUser|checkAuth|withAuth|verify_token|HTTPBasic|guard/i;
export const NON_PRODUCTION_GUARD = /if\s+not\s+[A-Za-z_.]*(?:is_)?prod|if\s+[A-Za-z_.]*(?:DEBUG|debug)\b|NODE_ENV\s*[!=]==?\s*['"]production|!==\s*['"]production|ENVIRONMENT\s*[!=]=\s*['"]production|\bdev(?:elopment)?_only\b/;
// A route the proxy answers itself is closed, whichever status it picks. 404
// belongs here as much as 403 — Caddy's `respond 404` is the idiomatic way to
// hide a path, and the report's own fix text tells the user that "a 401, 403
// or 404 is what you want to see", so flagging `respond 404` contradicted the
// advice two lines below it.
export const PROXY_DENY = /deny\s+all|return\s+40[0-9]|respond\s+40[0-9]|abort\s*\(\s*40[0-9]/;

// --- #6: security headers that only cover part of the site ---

export const CSP_HEADER = /Content-Security-Policy/i;
export const CSP_MENTION = /content[- ]security[- ]policy|\bCSP\b/i;

// --- #7: the server fetching any address a user hands it ---

// A URL that arrives in a request. Pydantic/FastAPI bodies, Express, Flask,
// Rails — the shapes an "import from URL" feature actually gets written in.
export const REQUEST_URL_SOURCE = /\b(?:HttpUrl|AnyHttpUrl|AnyUrl)\b|(?:req|request)\.(?:body|query|params|json|args|form|GET|POST)(?:\.|\[\s*['"])\s*[A-Za-z_]*(?:url|uri|link|src|href|endpoint|webhook|target|image)/i;
export const OUTBOUND_FETCH = /\b(?:httpx|requests|aiohttp|urllib3|session|client)\.(?:get|post|put|patch|request|stream)\s*\(|\burllib\.request\.urlopen\s*\(|\bAsyncClient\(\)[^\n]*\.(?:get|post)\s*\(|\bfetch\s*\(|\baxios(?:\.(?:get|post|put|request))?\s*\(|\bgot(?:\.(?:get|post))?\s*\(|Net::HTTP|HTTParty|\bcurl\s+["'$]/;
// Anything that resolves the address and refuses the private ones.
export const SSRF_GUARD = /ipaddress|ip_address|is_private|is_global|is_loopback|is_link_local|getaddrinfo|gethostbyname|allow(?:ed)?[_-]?(?:list|hosts|domains)|whitelist|blocklist|blacklist|denied_hosts|advocate|ssrf|validate_url|is_safe_url|safe_url|private_ip|169\.254\.169\.254/i;
export const FOLLOWS_REDIRECTS = /follow_redirects\s*=\s*True|allow_redirects\s*=\s*True|maxRedirects\s*:\s*[1-9]|redirect\s*:\s*['"]follow['"]|followRedirect\s*:\s*true/;
