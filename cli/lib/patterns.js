// Detection patterns for the deterministic layer.
// Rule of the house: every pattern here must be proven by a fixture in
// tests/fixtures — both that it catches the real shape and that it stays
// quiet on placeholders.

// Provider-specific formats. These are high-confidence: a match is treated as
// a real secret even if it "looks fake", because a real-shaped key must be
// rotated anyway once it has touched a tracked file.
export const SECRET_PATTERNS = [
  { id: 'aws-access-key', name: 'AWS access key', regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'anthropic-api-key', name: 'Anthropic API key', regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { id: 'stripe-live-key', name: 'Stripe live secret key', regex: /\bsk_live_[0-9a-zA-Z]{16,}\b/g },
  { id: 'stripe-test-key', name: 'Stripe test secret key', regex: /\bsk_test_[0-9a-zA-Z]{16,}\b/g, severity: 'medium' },
  { id: 'openai-api-key', name: 'OpenAI API key', regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g },
  { id: 'github-token', name: 'GitHub token', regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
  { id: 'google-api-key', name: 'Google API key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'slack-token', name: 'Slack token', regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { id: 'private-key-block', name: 'Private key material', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/g },
  { id: 'connection-string', name: 'Database URL with embedded password', regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^:/\s'"]+:[^@/\s'"]+@/g },
];

// Values that are clearly stand-ins, not real credentials. Only applied to
// generic matches — never to the provider-specific formats above.
const PLACEHOLDER = /xxx|\.\.\.|your[_-]?|example|sample|placeholder|change[_-]?me|dummy|fake[_-]|insert[_-]?|<[^>]*>|\$\{|%s|\bTODO\b/i;

export function looksPlaceholder(value) {
  return PLACEHOLDER.test(value);
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
// leading \b: it must also hit inside names like TEST_PASSWORD.
export const PASSWORD_ASSIGNMENT = /pass(?:word|wd)?[a-z0-9_]*\s*[:=]\s*['"][^'"\n]{4,}['"]/i;

// Quoted email that smells like a built-in account.
export const SUSPICIOUS_ACCOUNT_EMAIL = /['"][a-z0-9._%+-]*(?:admin|test|demo|root|superuser)[a-z0-9._%+-]*@[a-z0-9.-]+\.[a-z]{2,}['"]/i;

export const PERSONAL_PATH = /(?:\/(?:home|Users)\/[A-Za-z0-9._-]{3,}|[A-Z]:\\Users\\[A-Za-z0-9._-]{3,})/g;

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
