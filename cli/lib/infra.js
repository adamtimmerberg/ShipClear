// Deployment checks: the gap between "the code is clean" and "the thing you
// deployed is safe".
//
// Everything in checks.js asks whether a secret was written somewhere it
// shouldn't be. These checks ask a different question — whether the app is
// *running on* a value anyone can look up, whether a missing variable quietly
// becomes a known one, and whether the deployment hands a backing service,
// a storage bucket or a debug page straight to the internet. A scan can read
// all of that out of the config files that are already in the project.
//
// Unlike the rest of the gate these checks walk the working tree rather than
// git's tracked files: the live `.env` is the whole point of the first check
// and is (correctly) never tracked.
import path from 'node:path';
import {
  isSecretishKey, isKnownDefaultCredential, isLeftoverStandIn, isVariableReference,
  placeholderShapedCredential, productionSignal, maskSecret,
  SHELL_DEFAULT, CODE_DEFAULTS,
  MC_ANONYMOUS, AWS_PUBLIC_ACL, TF_PUBLIC_ACL, TF_PUBLIC_ACCESS_BLOCK_OFF,
  WILDCARD_PRINCIPAL, S3_ACTION, GCS_ALL_USERS, AZURE_PUBLIC_CONTAINER, FIREBASE_OPEN_RULE,
  PROXY_UPSTREAM_LINE, PROXY_ROUTE_LINE, HOST_PORT, BACKING_SERVICES, BACKING_PORTS,
  SENSITIVE_PATHS, ROUTE_DEFINITION, AUTH_NEARBY, NON_PRODUCTION_GUARD, PROXY_DENY,
  CSP_HEADER, CSP_MENTION,
  REQUEST_URL_SOURCE, OUTBOUND_FETCH, SSRF_GUARD, FOLLOWS_REDIRECTS,
} from './patterns.js';
import { walkFiles, isTextCandidate, readFileSafe } from './scan.js';

const base = (rel) => rel.split('/').pop();
const isEnvTemplate = (rel) => /^\.env(?:\..+)?\.(?:example|sample|template|dist)$|^\.env\.(?:example|sample|template|dist)$/.test(base(rel));
const isLiveEnv = (rel) => /^\.env(?:\..+)?$/.test(base(rel)) && !isEnvTemplate(rel);
const isCompose = (rel) => /^(?:docker-)?compose(?:[.-].+)?\.ya?ml$/i.test(base(rel));
const isTfVars = (rel) => /\.tfvars$/i.test(rel);
const isHelmValues = (rel) => /^values(?:[.-].+)?\.ya?ml$/i.test(base(rel));
const isYaml = (rel) => /\.ya?ml$/i.test(rel);
const isTerraform = (rel) => /\.tf$/i.test(rel);
const isDoc = (rel) => /\.(?:md|mdx|mdc|rst|txt)$/i.test(rel);
const isTestFile = (rel) => /(?:^|\/)(?:tests?|__tests__|spec|fixtures?)\//i.test(rel) || /\.(?:test|spec)\.[a-z]+$/i.test(rel);
const isProxyConfig = (rel) => /(?:^|\/)caddyfile|\.caddy$|nginx|traefik|envoy|haproxy|httpd\.conf$|\.vhost$|sites-(?:available|enabled)\//i.test(rel);
const isCodeFile = (rel) => /\.(?:js|cjs|mjs|jsx|ts|tsx|py|rb|go|php|java|kt|rs|cs|sh|bash)$/i.test(rel);

/** A dev-machine path like /media/* is a broad prefix; /media/logo.png isn't. */
const isBroadPrefix = (route) => !route || /[*]$|\/$|^\/[^/]*$/.test(route);

/**
 * Deployment-configuration findings for a project. Same shape as the rest of
 * the gate: { id, severity, file, line?, detail }.
 */
export function runInfraChecks(root, { ignored = () => false } = {}) {
  const findings = [];
  const files = walkFiles(root).filter((f) => !ignored(f) && isTextCandidate(f));
  const cache = new Map();
  const read = (rel) => {
    if (!cache.has(rel)) cache.set(rel, readFileSafe(path.join(root, rel)) ?? '');
    return cache.get(rel);
  };

  // --- is this project facing the public? ---
  // The same known password is untidy on a laptop and urgent on a domain.
  let production = null;
  for (const rel of files) {
    if (!isLiveEnv(rel) && !isCompose(rel) && !isYaml(rel) && !isTfVars(rel)) continue;
    const signal = productionSignal(read(rel));
    if (signal) { production = `${signal} in \`${rel}\``; break; }
  }

  const liveCredentials = inUseCredentials(files, read, production, findings);
  silentDefaults(files, read, liveCredentials, findings);
  publicStorage(files, read, findings);
  proxyTopology(files, read, findings);
  openDebugRoutes(files, read, findings);
  headerCoverage(files, read, findings);
  serverSideFetches(files, read, findings);
  return findings;
}

// ---------------------------------------------------------------------------
// #1 The app is running on a credential anybody can look up
// ---------------------------------------------------------------------------

// KEY=VALUE, as .env and .tfvars write it.
function envAssignments(content) {
  const out = [];
  content.split('\n').forEach((text, i) => {
    const m = text.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m || text.trim().startsWith('#')) return;
    out.push({ key: m[1], value: cleanValue(m[2]), line: i + 1 });
  });
  return out;
}

// Environment entries as YAML writes them: `- KEY=value`, `KEY: value`, and
// the k8s `- name: KEY` / `value: v` pair. Bare `key:` is skipped — lowercase
// YAML keys are ordinary structure, not credentials (see isSecretishKey).
function yamlAssignments(content) {
  const out = [];
  const lines = content.split('\n');
  lines.forEach((text, i) => {
    if (text.trim().startsWith('#')) return;
    let m = text.match(/^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (m) { out.push({ key: m[1], value: cleanValue(m[2]), line: i + 1 }); return; }
    m = text.match(/^\s*-?\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(\S.*)$/);
    if (m) {
      if (m[1] === 'name') {
        // k8s env entry: the value is on one of the next couple of lines.
        const value = (lines[i + 1] || '').match(/^\s*value\s*:\s*(\S.*)$/);
        if (value) out.push({ key: m[2].trim(), value: cleanValue(value[1]), line: i + 1 });
        return;
      }
      out.push({ key: m[1], value: cleanValue(m[2]), line: i + 1 });
    }
  });
  return out;
}

function cleanValue(raw) {
  let v = raw.trim();
  const quoted = v.match(/^(['"])(.*)\1/);
  if (quoted) return quoted[2];
  return v.replace(/\s+#.*$/, '').trim();
}

function assignmentsIn(rel, content) {
  if (isLiveEnv(rel) || isEnvTemplate(rel) || isTfVars(rel)) return envAssignments(content);
  if (isYaml(rel)) return yamlAssignments(content);
  return [];
}

function inUseCredentials(files, read, production, findings) {
  // What the project's own example file says — committed, therefore public.
  const examples = new Map();
  for (const rel of files.filter(isEnvTemplate)) {
    for (const { key, value } of envAssignments(read(rel))) {
      if (value) examples.set(`${key}=${value}`, rel);
    }
  }

  const live = new Map(); // key -> severity, for the escalation in #2
  const configFiles = files.filter(
    (rel) => isLiveEnv(rel) || isCompose(rel) || isTfVars(rel) || isHelmValues(rel)
      || (isYaml(rel) && /kind:\s*(?:Secret|Deployment|StatefulSet|ConfigMap|Pod)/.test(read(rel)))
  );

  for (const rel of configFiles) {
    const seen = new Set();
    const dbNote = /volumes\s*:/.test(read(rel)) && (isCompose(rel) || isYaml(rel));
    for (const { key, value, line } of assignmentsIn(rel, read(rel))) {
      if (!value || seen.has(key) || !isSecretishKey(key) || isVariableReference(value)) continue;

      let why = null;
      let weak = false;
      if (examples.has(`${key}=${value}`)) {
        why = `\`${key}\` is the same value as in your \`${examples.get(`${key}=${value}`)}\`, which is committed to your repo`;
      } else if (isKnownDefaultCredential(value)) {
        why = `\`${key}\` is \`${value}\` — the documented default for that service, and the first thing anyone tries`;
      } else if (isLeftoverStandIn(value)) {
        why = `\`${key}\` is \`${value}\` — a stand-in value that was never replaced`;
      } else if (placeholderShapedCredential(key, value)) {
        why = `\`${key}\` is still a placeholder (\`${maskSecret(value)}\`), not a generated secret`;
        weak = true;
      }
      if (!why) continue;
      // A short or placeholder-shaped value on a project with no sign of
      // being deployed anywhere is noise; a value published in the repo's
      // own example file is worth saying either way.
      if (weak && !production) continue;

      seen.add(key);
      const severity = production ? 'critical' : 'medium';
      live.set(key.toUpperCase(), severity);

      // One finding per file, not per variable: every value in a file needs
      // the same treatment (generate one, set it in both places), and three
      // copies of the same ten-line explanation read as three problems.
      const existing = findings.find((f) => f.id === 'credential-in-use-is-public' && f.file === rel);
      if (existing) {
        existing.reasons.push(why);
        existing.line = undefined;
        existing.detail = `${existing.reasons.length} values in this file are publicly known — `
          + `${existing.reasons.join('; ')}.`;
        existing.dbInContainer = existing.dbInContainer
          || (dbNote && /postgres|mysql|mariadb|mongo|redis|^db_|database/i.test(key));
        continue;
      }
      findings.push({
        id: 'credential-in-use-is-public',
        severity,
        file: rel,
        line,
        detail: why + '.',
        reasons: [why],
        production,
        dbInContainer: dbNote && /postgres|mysql|mariadb|mongo|redis|^db_|database/i.test(key),
      });
    }
  }
  return live;
}

// ---------------------------------------------------------------------------
// #2 A missing secret silently becomes a known one
// ---------------------------------------------------------------------------

// One finding per variable, not per file. A JWT secret read in five route
// files is one problem with one answer — five copies of the same ten-line
// explanation read as "do this five times" (the same reasoning as the
// per-commit grouping of history findings).
function silentDefaults(files, read, liveCredentials, findings) {
  const byKey = new Map();
  for (const rel of files) {
    if (isDoc(rel) || isEnvTemplate(rel) || isTestFile(rel)) continue;
    if (!isCompose(rel) && !isYaml(rel) && !isCodeFile(rel) && !isTerraform(rel) && !isProxyConfig(rel)) continue;
    const content = read(rel);
    const seen = new Set();

    const hit = (key, value, index) => {
      if (!value || seen.has(key) || !isSecretishKey(key)) return;
      seen.add(key);
      const line = lineAt(content, index);
      const existing = byKey.get(key.toUpperCase());
      if (existing) { existing.alsoAt.push(`${rel}:${line}`); return; }
      // Escalation: the fallback isn't hypothetical if check #1 found that
      // same variable running on a known value.
      const inUse = liveCredentials.get(key.toUpperCase());
      const finding = {
        id: 'secret-default-fallback',
        severity: inUse === 'critical' ? 'critical' : 'medium',
        file: rel,
        line,
        key,
        detail: `\`${key}\` falls back to \`${maskSecret(value)}\` when it isn't set`
          + (inUse ? ' — and that fallback is the value your config is actually using' : '')
          + '.',
        dbInContainer: /volumes\s*:/.test(content) && /postgres|mysql|mariadb|mongo|^db_|database/i.test(key),
        alsoAt: [],
      };
      byKey.set(key.toUpperCase(), finding);
      findings.push(finding);
    };

    SHELL_DEFAULT.lastIndex = 0;
    let m;
    while ((m = SHELL_DEFAULT.exec(content))) hit(m[1], cleanValue(m[2]), m.index);

    if (isCodeFile(rel)) {
      for (const pattern of CODE_DEFAULTS) {
        pattern.lastIndex = 0;
        let c;
        while ((c = pattern.exec(content))) {
          // The JS pattern has two alternative name groups (dot and bracket
          // access); the value is always the last captured group.
          const groups = c.slice(1).filter((g) => g !== undefined);
          hit(groups[0], groups[groups.length - 1], c.index);
        }
      }
    }
  }

  for (const f of byKey.values()) {
    if (!f.alsoAt.length) continue;
    const shown = f.alsoAt.slice(0, 4);
    const more = f.alsoAt.length - shown.length;
    f.detail += ` The same fallback is written in ${f.alsoAt.length} other `
      + `${f.alsoAt.length === 1 ? 'place' : 'places'}: ${shown.join(', ')}`
      + (more ? `, and ${more} more` : '') + ' — all of them need the same change.';
  }
}

// ---------------------------------------------------------------------------
// #3 Storage anyone can read — or list
// ---------------------------------------------------------------------------

function publicStorage(files, read, findings) {
  const add = (rel, index, content, severity, detail, listing = false) =>
    findings.push({ id: 'public-bucket', severity, file: rel, line: lineAt(content, index), detail, listing });

  for (const rel of files) {
    if (isDoc(rel) || isTestFile(rel)) continue;
    const content = read(rel);

    MC_ANONYMOUS.lastIndex = 0;
    let m;
    while ((m = MC_ANONYMOUS.exec(content))) {
      const policy = m[1].toLowerCase();
      if (policy === 'none') continue;
      const writable = policy === 'upload' || policy === 'write' || policy === 'public';
      add(rel, m.index, content,
        'critical',
        `\`${m[0].trim().replace(/["';]+$/, '')}\` — MinIO's \`${policy}\` policy lets anonymous users **list** the bucket`
          + (writable ? ' and upload to it' : '') + ', not just read a file they already have the link to.',
        true);
    }

    AWS_PUBLIC_ACL.lastIndex = 0;
    while ((m = AWS_PUBLIC_ACL.exec(content))) {
      add(rel, m.index, content, m[1] === 'public-read-write' ? 'critical' : 'medium',
        `\`--acl ${m[1]}\` makes the object or bucket readable${m[1] === 'public-read-write' ? ' *and writable*' : ''} by anyone.`);
    }

    TF_PUBLIC_ACL.lastIndex = 0;
    while ((m = TF_PUBLIC_ACL.exec(content))) {
      add(rel, m.index, content, m[1] === 'public-read-write' ? 'critical' : 'medium',
        `\`acl = "${m[1]}"\` on a bucket.`, m[1] === 'public-read-write');
    }

    TF_PUBLIC_ACCESS_BLOCK_OFF.lastIndex = 0;
    while ((m = TF_PUBLIC_ACCESS_BLOCK_OFF.exec(content))) {
      add(rel, m.index, content, 'medium',
        `\`${m[1]} = false\` switches off one of the guards that stops this bucket being made public by accident.`);
    }

    // A bucket policy with a wildcard principal: the actions decide how bad.
    WILDCARD_PRINCIPAL.lastIndex = 0;
    while ((m = WILDCARD_PRINCIPAL.exec(content))) {
      const scope = content.slice(m.index, m.index + 800);
      S3_ACTION.lastIndex = 0;
      const actions = [...scope.matchAll(S3_ACTION)].map((a) => a[1]);
      const listing = actions.some((a) => /ListBucket|s3:\*/.test(a));
      const writing = actions.some((a) => /PutObject|DeleteObject|s3:\*/.test(a));
      if (!actions.length) continue;
      add(rel, m.index, content, listing || writing ? 'critical' : 'medium',
        `a bucket policy grants \`${actions.join('`, `')}\` to everyone (\`"Principal": "*"\`)`
          + (listing ? ' — including permission to list the whole bucket' : '')
          + (writing ? ' — including permission to write or delete objects' : '') + '.',
        listing);
    }

    GCS_ALL_USERS.lastIndex = 0;
    while ((m = GCS_ALL_USERS.exec(content))) {
      const nearby = content.slice(Math.max(0, m.index - 300), m.index + 300);
      if (!/role|iam|member|gsutil|binding|storage/i.test(nearby)) continue;
      add(rel, m.index, content, 'critical',
        `\`${m[1]}\` in a storage IAM binding — that is literally "anyone on the internet", and the viewer role includes listing the bucket.`,
        true);
    }

    AZURE_PUBLIC_CONTAINER.lastIndex = 0;
    while ((m = AZURE_PUBLIC_CONTAINER.exec(content))) {
      const container = m[1].toLowerCase() === 'container';
      add(rel, m.index, content, container ? 'critical' : 'medium',
        `this container is public (\`${m[0].trim()}\`)`
          + (container ? ' — the `container` level also allows anonymous listing of everything inside' : '') + '.',
        container);
    }

    if (/\/(?:databases|storage|buckets)\/|rules_version|service\s+(?:cloud\.firestore|firebase\.storage)/.test(content)) {
      FIREBASE_OPEN_RULE.lastIndex = 0;
      while ((m = FIREBASE_OPEN_RULE.exec(content))) {
        const ops = m[1].trim();
        add(rel, m.index, content, /write/.test(ops) ? 'critical' : 'medium',
          `\`allow ${ops}: if true\` — every user, signed in or not, can ${ops.replace(/,\s*/g, ' and ')} this data.`,
          true);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// #4 A public route that forwards into a backing service
// ---------------------------------------------------------------------------

function proxyTopology(files, read, findings) {
  for (const rel of files) {
    const content = read(rel);
    const ingress = isYaml(rel) && /kind:\s*Ingress/.test(content);
    if (!isProxyConfig(rel) && !ingress) continue;
    if (isDoc(rel) || isTestFile(rel)) continue;

    const lines = content.split('\n');
    let route = null;
    const seen = new Set();
    lines.forEach((text, i) => {
      const r = text.match(PROXY_ROUTE_LINE);
      if (r) route = (r[1] || r[2] || '').trim();
      if (!PROXY_UPSTREAM_LINE.test(text)) return;

      HOST_PORT.lastIndex = 0;
      let hp;
      const candidates = [];
      while ((hp = HOST_PORT.exec(text))) candidates.push([hp[1].toLowerCase(), Number(hp[2])]);
      // Ingress and Traefik split host and port across lines; carry the
      // service name from whichever nearby line names it.
      if (!candidates.length) {
        const name = text.match(/(?:serviceName|service_name|name)\s*:\s*['"]?([a-z0-9-]+)/i);
        const port = (lines[i + 1] || '') + (lines[i + 2] || '');
        const num = port.match(/(?:number|port)\s*:\s*(\d{2,5})/);
        if (name) candidates.push([name[1].toLowerCase(), num ? Number(num[1]) : 0]);
      }

      for (const [host, port] of candidates) {
        const service = Object.keys(BACKING_SERVICES).find((s) => host === s || host.includes(s))
          || BACKING_PORTS[port];
        if (!service || !BACKING_SERVICES[service]) continue;
        if (seen.has(service + route)) continue;
        seen.add(service + route);
        findings.push({
          id: 'proxy-exposes-service',
          severity: BACKING_SERVICES[service],
          file: rel,
          line: i + 1,
          detail: `the public route \`${route || '/'}\` forwards to \`${host}${port ? ':' + port : ''}\` (${service})`
            + (isBroadPrefix(route) ? ' — and it is a catch-all prefix, so that service\'s own admin and API endpoints are reachable too' : '')
            + '.',
          service,
          route: route || '/',
        });
      }
    });
  }
}

// ---------------------------------------------------------------------------
// #5 Debug and monitoring pages open to the public
// ---------------------------------------------------------------------------

function openDebugRoutes(files, read, findings) {
  for (const rel of files) {
    if (isDoc(rel) || isTestFile(rel)) continue;
    const proxy = isProxyConfig(rel);
    if (!isCodeFile(rel) && !proxy) continue;
    const content = read(rel);
    const lines = content.split('\n');
    const seen = new Set();

    const consider = (route, lineIndex) => {
      const normalized = route.replace(/\/+$/, '').replace(/\*$/, '').toLowerCase() || '/';
      const match = Object.keys(SENSITIVE_PATHS).find(
        (p) => normalized === p || normalized.startsWith(p + '/') || normalized.endsWith(p)
      );
      if (!match || seen.has(match)) return;
      const nearby = lines.slice(Math.max(0, lineIndex - 4), lineIndex + 5).join('\n');
      // Already protected, or deliberately absent outside development —
      // `docs_url="/api/docs" if not settings.is_production else None` is the
      // pattern we *want* people to use, so it must stay quiet.
      if (AUTH_NEARBY.test(nearby) || NON_PRODUCTION_GUARD.test(nearby)) return;
      if (proxy && PROXY_DENY.test(nearby)) return;
      seen.add(match);
      findings.push({
        id: 'debug-route-public',
        severity: SENSITIVE_PATHS[match],
        file: rel,
        line: lineIndex + 1,
        detail: `\`${route}\` is served with no sign of an authentication check or a production switch.`,
      });
    };

    lines.forEach((text, i) => {
      ROUTE_DEFINITION.lastIndex = 0;
      let m;
      while ((m = ROUTE_DEFINITION.exec(text))) {
        const route = m[1] || m[2] || m[3] || m[4];
        if (route && route.startsWith('/')) consider(route, i);
      }
      if (proxy) {
        const r = text.match(PROXY_ROUTE_LINE);
        const route = r && (r[1] || r[2]);
        if (route && route.startsWith('/')) consider(route, i);
      }
    });
  }
}

// ---------------------------------------------------------------------------
// #6 Security headers that only cover part of the site
// ---------------------------------------------------------------------------

function headerCoverage(files, read, findings) {
  // (a) A proxy config that talks about CSP in its comments and sets none.
  // The comment is the tell: someone believed this was handled.
  for (const rel of files.filter(isProxyConfig)) {
    const content = read(rel);
    if (CSP_HEADER.test(content.replace(/^\s*[#;].*$/gm, ''))) continue;
    const lines = content.split('\n');
    const claim = lines.findIndex((l) => /^\s*[#;]/.test(l) && CSP_MENTION.test(l));
    if (claim === -1) continue;
    findings.push({
      id: 'headers-html-uncovered',
      severity: 'medium',
      file: rel,
      line: claim + 1,
      detail: 'this file\'s comments describe a Content-Security-Policy, but it does not set one.',
    });
  }

  // (b) A CSP that exists, but only on the API — the half of the app that
  // doesn't run scripts. The pages people load in a browser get nothing.
  const withCsp = files.filter((rel) => !isDoc(rel) && !isTestFile(rel) && CSP_HEADER.test(read(rel)));
  if (!withCsp.length) return; // no CSP anywhere is a different (semantic) conversation
  const apiOnly = withCsp.every((rel) => /["'`]\/api/.test(read(rel)) || /\/api/.test(rel));
  if (!apiOnly) return;
  const htmlSurface = files.find(
    (rel) => /^(?:frontend\/|web\/|client\/)?(?:next|nuxt|vite|svelte|remix|astro)\.config\.[a-z]+$/i.test(rel)
      || base(rel) === 'index.html'
  ) || files.find((rel) => isProxyConfig(rel) && /^\s*(?:handle|route|location|reverse_proxy)\s+\/\s*[{\n]/m.test(read(rel)));
  if (!htmlSurface) return;
  findings.push({
    id: 'headers-html-uncovered',
    severity: 'medium',
    file: withCsp[0],
    detail: `the Content-Security-Policy here is scoped to \`/api\`, but the pages a browser actually loads are served elsewhere (\`${htmlSurface}\`) with no policy.`,
  });
}

// ---------------------------------------------------------------------------
// #7 The server fetching any address a user hands it
// ---------------------------------------------------------------------------

function serverSideFetches(files, read, findings) {
  for (const rel of files) {
    if (!isCodeFile(rel) || isDoc(rel) || isTestFile(rel)) continue;
    const content = read(rel);
    if (!REQUEST_URL_SOURCE.test(content)) continue;
    const lines = content.split('\n');
    const call = lines.findIndex((l) => OUTBOUND_FETCH.test(l));
    if (call === -1) continue;

    const guarded = SSRF_GUARD.test(content);
    const redirects = FOLLOWS_REDIRECTS.test(content);
    if (guarded && !redirects) continue;
    findings.push({
      id: 'ssrf-unchecked-fetch',
      severity: 'high',
      file: rel,
      line: call + 1,
      detail: guarded
        ? 'this fetch of a user-supplied address follows redirects, which steps around the address check above it — a redirect to `169.254.169.254` or `localhost` passes.'
        : 'a web address that arrives in a request is fetched by the server with no check that it points at the public internet.',
      redirectsOnly: guarded,
    });
  }
}

function lineAt(content, index) {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}
