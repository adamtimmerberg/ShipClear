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

// Provider-specific formats. These are high-confidence: a match is treated as
// a real secret even if it "looks fake", because a real-shaped key must be
// rotated anyway once it has touched a tracked file. A pattern may carry a
// `validate(match)` to veto matches that are provably templates.
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
  { id: 'private-key-block', name: 'Private key material', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/g },
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
export function findSecrets(content, { includeGeneric = true } = {}) {
  const raw = [];
  for (const p of SECRET_PATTERNS) {
    p.regex.lastIndex = 0;
    let m;
    while ((m = p.regex.exec(content))) {
      if (p.validate && !p.validate(m[0])) continue;
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
  const kept = [];
  for (const cand of raw) {
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
export const PASSWORD_ASSIGNMENT = /pass(?:word|wd)?[a-z0-9_]*["']?\s*[:=]\s*['"][^'"\n]{4,}['"]/i;

// Quoted email that smells like a built-in account.
export const SUSPICIOUS_ACCOUNT_EMAIL = /['"][a-z0-9._%+-]*(?:admin|test|demo|root|superuser)[a-z0-9._%+-]*@[a-z0-9.-]+\.[a-z]{2,}['"]/i;

// The lookbehind requires an absolute-path boundary: `"/home/adam"` matches,
// but the `/home/` inside an import like `components/home/card` does not
// (found the hard way on the precedent starter repo).
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
