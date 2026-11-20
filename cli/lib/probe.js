// The live probe: ask the deployed app what is actually reachable.
//
// Three of the findings on the real app that prompted these checks were
// invisible in source — a bucket policy applied at runtime by a one-shot
// container, a proxy route's real behaviour, a response header that isn't
// there. Five were confirmable with a single GET each. This is the difference
// between "your config looks risky" and "anyone can list your users' uploads
// right now, here is the URL".
//
// Hard rules, enforced here and not negotiable elsewhere in the codebase:
//   • GET and HEAD only. Nothing is ever written, posted, or deleted.
//   • No credentials, cookies, or auth headers are sent, and no login or
//     auth-bypass is ever attempted. A 401 or 403 is a pass, not a puzzle.
//   • Only the URL the user typed, and paths beneath it.
//   • Opt-in per run (`ship --probe <url>`), after an explicit confirmation.
// The HTTP layer is injected so the whole thing is testable without a network.
import { SENSITIVE_PATHS } from './patterns.js';

const HEADERS_THAT_PROTECT_PAGES = [
  ['content-security-policy', 'Content-Security-Policy (stops injected scripts running)'],
  ['strict-transport-security', 'Strict-Transport-Security (forces https)'],
  ['x-frame-options', 'X-Frame-Options or a frame-ancestors policy (stops your site being framed)'],
  ['x-content-type-options', 'X-Content-Type-Options (stops content-type guessing)'],
];

// A response body that is an index of a bucket's contents, in the shapes S3,
// MinIO and ordinary directory listings produce.
const LOOKS_LIKE_A_LISTING = /<ListBucketResult|<Key>|"Contents"\s*:|<title>Index of|Directory listing for/i;

/** Normalize what a user typed into an origin we can append paths to. */
export function normalizeBase(input) {
  const scheme = String(input).match(/^([a-z][a-z0-9+.-]*):/i);
  if (scheme && !/^https?$/i.test(scheme[1])) {
    return { error: `Only http:// and https:// addresses can be probed (\`${scheme[1]}:\` is not one).` };
  }
  const withScheme = /^https?:\/\//i.test(input) ? input : `https://${input}`;
  let url;
  try {
    url = new URL(withScheme);
  } catch {
    return { error: `\`${input}\` is not a web address ShipClear can read.` };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { error: 'Only http:// and https:// addresses can be probed.' };
  }
  return { base: url.origin + url.pathname.replace(/\/+$/, '') };
}

/** One request, built so it cannot be anything but a read. */
async function httpRead(url, method) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(url, {
      method,
      redirect: 'manual',
      headers: { 'user-agent': 'ShipClear probe (read-only)' },
      signal: controller.signal,
    });
    const headers = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    let body = '';
    if (method === 'GET') body = (await res.text()).slice(0, 4096);
    return { status: res.status, headers, body };
  } catch (err) {
    return { error: err.name === 'AbortError' ? 'no answer within 8 seconds' : err.message };
  } finally {
    clearTimeout(timer);
  }
}

const reachable = (res) => !res.error && res.status >= 200 && res.status < 300;

/**
 * Probe a deployed app. `staticFindings` is the deterministic layer's output:
 * findings it already made are *confirmed* in place (escalated and reworded)
 * rather than reported twice, so the report says "proven", not "and also".
 * Returns { findings, notes, requests }.
 */
export async function runProbe(baseUrl, staticFindings = [], { request = httpRead } = {}) {
  const { base, error } = normalizeBase(baseUrl);
  if (error) return { findings: [], notes: [`Probe skipped: ${error}`], requests: 0 };

  const findings = [];
  const notes = [];
  let requests = 0;
  const get = async (path) => { requests++; return request(base + path, 'GET'); };

  // Some apps answer 200 with the same page for every path (SPA catch-alls).
  // Without this, every probe below would "find" everything.
  const sentinel = await get(`/shipclear-probe-${Math.random().toString(36).slice(2, 10)}`);
  const answersEverything = reachable(sentinel);
  if (sentinel.error) {
    return {
      findings: [],
      notes: [`Probe could not reach ${base} (${sentinel.error}) — nothing was tested. Check the address, or that the site is up.`],
      requests,
    };
  }
  const differsFromSentinel = (res) =>
    !answersEverything
    || res.headers['content-type'] !== sentinel.headers['content-type']
    || Math.abs(res.body.length - sentinel.body.length) > 64;
  if (answersEverything) {
    notes.push('This site answers 200 for addresses that do not exist, so the probe only reported pages whose response actually differed from that catch-all.');
  }

  // --- the headers on the response that is an actual page ---
  const root = await get('/');
  if (reachable(root)) {
    const missing = HEADERS_THAT_PROTECT_PAGES.filter(([h]) => !root.headers[h]);
    // frame-ancestors in a CSP does the job of X-Frame-Options.
    const csp = root.headers['content-security-policy'] || '';
    const stillMissing = missing.filter(([h]) => !(h === 'x-frame-options' && /frame-ancestors/i.test(csp)));
    if (stillMissing.length) {
      const existing = staticFindings.find((f) => f.id === 'headers-html-uncovered');
      const detail = `your live home page is served without ${stillMissing.length} of these headers: `
        + `${stillMissing.map(([, label]) => label).join('; ')}. Checked just now with a single request to ${base}/.`;
      if (existing) {
        existing.detail = detail;
        existing.probeConfirmed = true;
      } else {
        findings.push({ id: 'headers-html-uncovered', severity: 'medium', file: `${base}/`, detail, probeConfirmed: true });
      }
    } else {
      notes.push(`Probe: your home page does send the headers that protect pages (checked ${base}/).`);
    }
  }

  // --- debug and monitoring pages, as the internet sees them ---
  for (const [path, staticSeverity] of Object.entries(SENSITIVE_PATHS)) {
    const res = await get(path);
    if (!reachable(res) || !differsFromSentinel(res)) continue;
    // A suspected-open route that is *proven* open is worse than suspected.
    const severity = staticSeverity === 'critical' ? 'critical' : 'high';
    // Deliberately not "from the internet": the address might be a staging
    // host or localhost, and the claim has to stay true for whatever was typed.
    const detail = `\`GET ${path}\` answered ${res.status} to a request carrying no login of any kind. Verified just now against ${base}.`;
    const existing = staticFindings.find((f) => f.id === 'debug-route-public' && (f.detail || '').includes(path));
    if (existing) {
      existing.severity = severity;
      existing.detail = `${existing.detail} Confirmed live: ${detail}`;
      existing.probeConfirmed = true;
    } else {
      findings.push({ id: 'debug-route-public', severity, file: `${base}${path}`, detail, probeConfirmed: true });
    }
  }

  // --- the storage prefixes the proxy config pointed at ---
  for (const f of staticFindings.filter((x) => x.id === 'proxy-exposes-service')) {
    const prefix = (f.route || '/').replace(/\*+$/, '').replace(/\/+$/, '');
    const listing = await get(`${prefix}/`);
    if (reachable(listing) && LOOKS_LIKE_A_LISTING.test(listing.body)) {
      findings.push({
        id: 'public-bucket',
        severity: 'critical',
        file: `${base}${prefix}/`,
        listing: true,
        probeConfirmed: true,
        detail: `\`GET ${prefix}/\` returned a list of the files in your storage, to a request with no login. Anyone with this address can read that list and download what is in it. This is not a reading of your config — it is what your live site answered just now.`,
      });
    }
    // The service's own API answering through the route is the proof that the
    // route forwards more than the files it was meant to serve.
    const health = await get(`${prefix}/minio/health/live`);
    if (reachable(health)) {
      f.severity = f.severity === 'critical' ? 'critical' : 'high';
      f.probeConfirmed = true;
      f.detail = `${f.detail} Confirmed live: \`GET ${prefix}/minio/health/live\` answered ${health.status}, so the service's own API — not just your files — is reachable from the internet.`;
    }
  }

  notes.push(`Probe: ${requests} read-only requests to ${base} (GET only; nothing was written, no logins attempted).`);
  return { findings, notes, requests };
}
