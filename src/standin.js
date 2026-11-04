/**
 * standin — reversible redaction for text you hand to an LLM.
 *
 * scan(text)   -> findings + redacted text + a vault that maps placeholders back
 * restore(text, vault) -> the model's answer with real values put back
 *
 * Zero dependencies. Runs in a browser tab, in Node, anywhere JS runs.
 * MIT licensed.
 */

export const VERSION = '0.1.0';

/** Categories drive the UI filters and the `categories` option. */
export const CATEGORIES = {
  secrets: { label: 'Secrets & credentials', short: 'Secrets', rank: 5, defaultOn: true },
  finance: { label: 'Financial', short: 'Finance', rank: 4, defaultOn: true },
  identity: { label: 'Identity numbers', short: 'Identity', rank: 4, defaultOn: true },
  contact: { label: 'Contact details', short: 'Contact', rank: 3, defaultOn: true },
  network: { label: 'Network & infrastructure', short: 'Network', rank: 2, defaultOn: true },
  people: { label: 'Names & addresses', short: 'People', rank: 1, defaultOn: false },
};

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];

/* ------------------------------------------------------------------ */
/* small numeric helpers                                              */
/* ------------------------------------------------------------------ */

const digits = (s) => s.replace(/\D/g, '');

function luhn(value) {
  const d = digits(value);
  if (d.length < 13 || d.length > 19) return false;
  if (/^(\d)\1+$/.test(d)) return false; // 0000…, 1111…
  let sum = 0;
  let double = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

function mod97(value) {
  let s = value.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
  if (s.length < 15 || s.length > 34) return false;
  s = s.slice(4) + s.slice(0, 4);
  let rest = 0;
  for (const ch of s) {
    const chunk = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const c of chunk) rest = (rest * 10 + (c.charCodeAt(0) - 48)) % 97;
  }
  return rest === 1;
}

export function entropy(str) {
  if (!str.length) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/* ------------------------------------------------------------------ */
/* rule plumbing                                                      */
/* ------------------------------------------------------------------ */

function regexRule(id, tag, label, category, severity, pattern, opts = {}) {
  return {
    id,
    tag,
    label,
    category,
    severity,
    experimental: !!opts.experimental,
    defaultOn: opts.defaultOn !== false,
    find(text) {
      const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
      const re = new RegExp(pattern.source, flags);
      const out = [];
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) {
          re.lastIndex += 1;
          continue;
        }
        const group = opts.group == null ? 0 : opts.group;
        const raw = m[group];
        if (raw == null || !raw.length) continue;
        const offset = group === 0 ? 0 : m[0].indexOf(raw);
        const start = m.index + (offset < 0 ? 0 : offset);
        const end = start + raw.length;
        if (opts.accept && !opts.accept(raw, text, start, end)) continue;
        out.push({ start, end, value: raw });
      }
      return out;
    },
  };
}

function customRule(id, tag, label, category, severity, find, opts = {}) {
  return {
    id,
    tag,
    label,
    category,
    severity,
    experimental: !!opts.experimental,
    defaultOn: opts.defaultOn !== false,
    find,
  };
}

const PLACEHOLDERISH =
  /^(?:\[[A-Z0-9_]+\]|\{\{[^}]*\}\}|<[^>]*>|\$\{[^}]*\}|process\.env|\*{3,}|x{3,}|·+|redacted|hidden|null|none|true|false|undefined|string|changeme|your[-_ ]?key)$/i;

const looksLikePlaceholder = (v) => PLACEHOLDERISH.test(v.trim()) || /^[$%]/.test(v) || /^env[.:]/i.test(v);

/* ------------------------------------------------------------------ */
/* the rules — order is precedence: earlier rules win overlaps        */
/* ------------------------------------------------------------------ */

export const RULES = [
  regexRule(
    'private-key',
    'PRIVATE_KEY',
    'Private key block',
    'secrets',
    'critical',
    /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]{0,8000}?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g
  ),
  regexRule(
    'jwt',
    'JWT',
    'JSON Web Token',
    'secrets',
    'critical',
    /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g
  ),
  regexRule('openai-key', 'API_KEY', 'OpenAI / Anthropic style key', 'secrets', 'critical', /\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}\b/g),
  regexRule('aws-key', 'AWS_KEY', 'AWS access key id', 'secrets', 'critical', /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{12,20}\b/g),
  regexRule(
    'aws-secret',
    'AWS_SECRET',
    'AWS secret access key',
    'secrets',
    'critical',
    /\baws_?secret_?(?:access_?)?key\b\s*[:=]\s*["']?([A-Za-z0-9/+=]{30,45})/gi,
    { group: 1 }
  ),
  regexRule('github-token', 'GH_TOKEN', 'GitHub token', 'secrets', 'critical', /\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{30,255})\b/g),
  regexRule('slack-token', 'SLACK_TOKEN', 'Slack token', 'secrets', 'critical', /\bxox[abposre]-[A-Za-z0-9-]{10,}\b/g),
  regexRule('google-key', 'GOOGLE_KEY', 'Google API key', 'secrets', 'critical', /\bAIza[0-9A-Za-z_-]{35}\b/g),
  regexRule('stripe-key', 'STRIPE_KEY', 'Stripe key', 'secrets', 'critical', /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g),
  regexRule('bearer', 'TOKEN', 'Bearer token', 'secrets', 'critical', /\bBearer\s+([A-Za-z0-9._~+/-]{16,})/gi, { group: 1 }),
  regexRule(
    'credential-url',
    'CRED_URL',
    'URL with embedded credentials',
    'secrets',
    'critical',
    /\b[a-z][a-z0-9+.-]{1,12}:\/\/[^\s/:@]+:[^\s/:@]+@[^\s/?#]+/gi
  ),
  customRule(
    'secret-assignment',
    'SECRET',
    'Password or secret in a key/value pair',
    'secrets',
    'critical',
    (text) => {
      const re =
        /\b([A-Za-z0-9_.-]{0,30}?(?:api[_-]?key|key|secret|token|password|passwd|pwd|passphrase|credential)(?:[_][A-Za-z0-9_]{1,14})?)\b\s*[:=]\s*["']?([^\s"',;<>{}[\]`]{6,200})/gi;
      const out = [];
      let m;
      while ((m = re.exec(text)) !== null) {
        const value = m[2];
        if (looksLikePlaceholder(value)) continue;
        if (/^\d{1,6}$/.test(value)) continue;
        const start = m.index + m[0].lastIndexOf(value);
        out.push({ start, end: start + value.length, value });
      }
      return out;
    }
  ),
  customRule(
    'high-entropy',
    'SECRET',
    'High-entropy string (looks like a key)',
    'secrets',
    'high',
    (text) => {
      const re = /[A-Za-z0-9+/_=-]{24,200}/g;
      const out = [];
      let m;
      while ((m = re.exec(text)) !== null) {
        const token = m[0];
        // trim trailing punctuation-ish chars that are usually not part of a key
        const trimmed = token.replace(/[=_-]+$/, '');
        if (trimmed.length < 24) continue;
        const start = m.index;
        const value = trimmed.slice(0, trimmed.length);
        const isHex = /^[0-9a-f]+$/i.test(value);
        if (isHex) {
          if (!/[0-9]/.test(value) || entropy(value) < 3.0) continue;
        } else {
          const mixed = /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value);
          if (!mixed || entropy(value) < 3.6) continue;
        }
        if (/^[\d-]+$/.test(value)) continue; // dates, phone-ish runs
        const before = text.slice(Math.max(0, start - 24), start);
        if (/(?:commit|sha|hash|revision|rev|blob|tree|digest|etag|base64|data:)[\s:#,]{0,3}$/i.test(before)) continue;
        out.push({ start, end: start + value.length, value });
      }
      return out;
    }
  ),
  customRule(
    'card',
    'CARD',
    'Payment card number',
    'finance',
    'high',
    (text) => {
      const re = /\b(?:\d[ -]?){12,18}\d\b/g;
      const out = [];
      let m;
      while ((m = re.exec(text)) !== null) {
        if (!luhn(m[0])) continue;
        out.push({ start: m.index, end: m.index + m[0].length, value: m[0] });
      }
      return out;
    }
  ),
  customRule(
    'iban',
    'IBAN',
    'Bank account (IBAN)',
    'finance',
    'high',
    (text) => {
      const re = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){1,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g;
      const out = [];
      let m;
      while ((m = re.exec(text)) !== null) {
        if (!mod97(m[0])) continue;
        out.push({ start: m.index, end: m.index + m[0].length, value: m[0] });
      }
      return out;
    }
  ),
  regexRule(
    'crypto-eth',
    'WALLET',
    'Crypto wallet address',
    'finance',
    'high',
    /\b0x[a-fA-F0-9]{40}\b/g
  ),
  regexRule(
    'crypto-btc',
    'WALLET',
    'Crypto wallet address',
    'finance',
    'high',
    /\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g
  ),
  regexRule('ssn', 'SSN', 'US Social Security number', 'identity', 'high', /\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b/g, {
    accept: (v) => /[- ]/.test(v),
  }),
  regexRule('ein', 'EIN', 'US employer ID number', 'identity', 'medium', /\b\d{2}-\d{7}\b/g),
  customRule(
    'ipv4',
    'IP',
    'IP address',
    'network',
    'medium',
    (text) => {
      const re = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
      const out = [];
      let m;
      while ((m = re.exec(text)) !== null) {
        const v = m[0];
        if (/^(?:127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.255)$/.test(v)) continue;
        out.push({ start: m.index, end: m.index + v.length, value: v });
      }
      return out;
    }
  ),
  regexRule(
    'ipv6',
    'IP',
    'IPv6 address',
    'network',
    'medium',
    /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,6}:(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){0,5})?\b/g
  ),
  regexRule('mac', 'MAC', 'Hardware address', 'network', 'low', /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g),
  regexRule(
    'url-secret',
    'URL',
    'URL carrying a secret parameter',
    'network',
    'medium',
    /\bhttps?:\/\/[^\s"'<>]+[?&](?:token|key|api[_-]?key|secret|sig|expires|signature|password|session|access_token)=[^\s"'&#]+/gi
  ),
  regexRule(
    'email',
    'EMAIL',
    'Email address',
    'contact',
    'medium',
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?){0,4}\.[A-Za-z]{2,24}\b/g
  ),
  customRule('phone', 'PHONE', 'Phone number', 'contact', 'medium', (text) => {
    const re = /\+\d[\d ()./-]{7,20}\d|\b\(?\d{2,4}\)?[ .-]\d{2,4}[ .-]\d{2,5}(?:[ .-]\d{1,5})?\b/g;
    const out = [];
    let m;
    while ((m = re.exec(text)) !== null) {
      const v = m[0].trim();
      const d = digits(v);
      if (d.length < 9 || d.length > 15) continue;
      if (/^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}$/.test(v)) continue; // date
      if (/^(?:19|20)\d{2}$/.test(v)) continue;
      if (/^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:\d{1,3})){3}$/.test(v)) continue; // ip
      if (!/[ ().+-]/.test(v)) continue; // bare digits are handled elsewhere
      if ((v.match(/\b\d{4}\b/g) || []).length >= 3) continue; // 4-4-4 groups are card/account shaped
      out.push({ start: m.index, end: m.index + m[0].length, value: v });
    }
    return out;
  }),
  regexRule(
    'address',
    'ADDRESS',
    'Street address',
    'people',
    'medium',
    /\b\d{1,5}\s+(?:[A-Z][A-Za-z0-9.'-]+\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Close|Crescent)\b\.?(?:,?\s+[A-Z][A-Za-z.'-]+){0,2}(?:[,\s]+\d{5}(?:-\d{4})?)?/g,
    { experimental: true }
  ),
  regexRule(
    'name-honorific',
    'NAME',
    'Person name',
    'people',
    'medium',
    /\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){0,2})\b/g,
    { group: 1, experimental: true }
  ),
  regexRule(
    'name-context',
    'NAME',
    'Person name',
    'people',
    'medium',
    /(?:\b[Mm]y name is|\b[Nn]ame is|\b[Ii] am|\bI'm|\b[Tt]his is|\b[Ss]igned,|\b[Rr]egards,|\b[Tt]hanks,)\s+([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){0,2})\b/g,
    { group: 1, experimental: true }
  ),
];

const RULE_BY_ID = new Map(RULES.map((r) => [r.id, r]));

export function rulesFor(opts = {}) {
  const categories = opts.categories
    ? new Set(Array.isArray(opts.categories) ? opts.categories : [opts.categories])
    : null;
  return RULES.filter((rule) => {
    if (rule.experimental && !opts.experimental) return false;
    if (!rule.defaultOn && !opts.includeOffByDefault) return false;
    if (categories && !categories.has(rule.category)) return false;
    return true;
  });
}

/* ------------------------------------------------------------------ */
/* scanning                                                           */
/* ------------------------------------------------------------------ */

function overlaps(a, b) {
  return a.start < b.end && b.start < a.end;
}

/**
 * Scan text and return everything the UI needs.
 *
 * @param {string} text
 * @param {object} [opts]
 * @param {string[]} [opts.categories]   limit to these categories
 * @param {boolean} [opts.experimental]  include names & addresses
 * @param {'bracket'|'brace'} [opts.mask]
 * @param {Array} [opts.vault]           existing vault, to keep placeholders stable
 */
export function scan(text, opts = {}) {
  const src = typeof text === 'string' ? text : '';
  const mask = opts.mask === 'brace' ? 'brace' : 'bracket';
  const ruleList = rulesFor(opts);

  const candidates = [];
  for (const rule of ruleList) {
    let found;
    try {
      found = rule.find(src);
    } catch {
      found = [];
    }
    for (const hit of found) candidates.push({ ...hit, rule });
  }

  // Greedy precedence: rule order first (specific beats generic), then longest match.
  candidates.sort((a, b) => {
    const pa = RULES.indexOf(a.rule);
    const pb = RULES.indexOf(b.rule);
    if (pa !== pb) return pa - pb;
    return b.end - b.start - (a.end - a.start);
  });

  const accepted = [];
  for (const cand of candidates) {
    if (accepted.some((a) => overlaps(a, cand))) continue;
    accepted.push(cand);
  }
  accepted.sort((a, b) => a.start - b.start);

  // Merge nested/sibling matches from the same rule that are only separated by
  // whitespace (e.g. a private key header and body found twice).
  const vault = new Map(); // value -> entry
  const counters = new Map();
  const seeded = Array.isArray(opts.vault) ? opts.vault : [];
  for (const entry of seeded) {
    if (!entry || !entry.placeholder || entry.value == null) continue;
    vault.set(entry.value, entry);
    const tag = entry.tag || 'VALUE';
    counters.set(tag, Math.max(counters.get(tag) || 0, Number(entry.index) || 0));
  }

  const wrap = (id) => (mask === 'brace' ? `{{${id}}}` : `[${id}]`);
  const findings = [];
  const inVault = new Set();

  for (const hit of accepted) {
    const key = hit.value;
    let entry = vault.get(key);
    if (!entry) {
      const tag = hit.rule.tag;
      const n = (counters.get(tag) || 0) + 1;
      counters.set(tag, n);
      entry = {
        placeholder: wrap(`${tag}_${n}`),
        id: `${tag}_${n}`,
        tag,
        index: n,
        value: key,
        ruleId: hit.rule.id,
        label: hit.rule.label,
        category: hit.rule.category,
        severity: hit.rule.severity,
      };
      vault.set(key, entry);
    }
    inVault.add(entry.placeholder);
    findings.push({
      ...entry,
      start: hit.start,
      end: hit.end,
      seen: findings.some((f) => f.placeholder === entry.placeholder),
    });
  }

  let redacted = '';
  let cursor = 0;
  for (const hit of accepted) {
    const entry = vault.get(hit.value);
    redacted += src.slice(cursor, hit.start) + entry.placeholder;
    cursor = hit.end;
  }
  redacted += src.slice(cursor);

  const entries = [...vault.values()].sort(
    (a, b) => (CATEGORIES[a.category]?.rank ?? 0) - (CATEGORIES[b.category]?.rank ?? 0) || a.placeholder.localeCompare(b.placeholder)
  );

  const byCategory = {};
  for (const entry of entries) byCategory[entry.category] = (byCategory[entry.category] || 0) + 1;

  const severityCount = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const entry of entries) severityCount[entry.severity] = (severityCount[entry.severity] || 0) + 1;

  return {
    source: src,
    redacted,
    findings,
    vault: entries,
    byCategory,
    severityCount,
    total: entries.length,
    placeholders: accepted.length,
    changed: redacted !== src,
  };
}

/** Convenience: text in, redacted text + vault out. */
export function redact(text, opts = {}) {
  const result = scan(text, opts);
  return { text: result.redacted, vault: result.vault, findings: result.findings, total: result.total };
}

const PLACEHOLDER_RE = /\[([A-Z][A-Z0-9]{0,24}_\d{1,6})\]|\{\{([A-Z][A-Z0-9]{0,24}_\d{1,6})\}\}/g;

/**
 * Put real values back into a model's answer.
 * Tolerant: works even if the model dropped brackets or added code ticks.
 */
export function restore(text, vault) {
  const map = new Map();
  const list = Array.isArray(vault) ? vault : Array.isArray(vault?.vault) ? vault.vault : [];
  for (const entry of list) {
    if (!entry || entry.placeholder == null) continue;
    map.set(entry.placeholder, entry.value);
    if (entry.id) {
      map.set(`[${entry.id}]`, entry.value);
      map.set(`{{${entry.id}}}`, entry.value);
    }
  }
  let out = typeof text === 'string' ? text : '';
  out = out.replace(PLACEHOLDER_RE, (whole, a, b) => {
    const id = a || b;
    return map.get(`[${id}]`) ?? map.get(`{{${id}}}`) ?? whole;
  });
  // last resort: bare EMAIL_1 / CARD_2 tokens
  out = out.replace(/\b([A-Z][A-Z0-9]{0,24}_\d{1,6})\b/g, (whole) => map.get(`[${whole}]`) ?? map.get(`{{${whole}}}`) ?? whole);
  return out;
}

/** Report how much of a restore actually resolved. */
export function restoreReport(text, vault) {
  const restored = restore(text, vault);
  const list = Array.isArray(vault) ? vault : vault?.vault ?? [];
  const present = new Set(list.filter((e) => typeof text === 'string' && (text.includes(e.placeholder) || (e.id && new RegExp(`\\b${e.id}\\b`).test(text)))).map((e) => e.placeholder));
  return { text: restored, resolved: present.size, unresolved: list.length - present.size };
}

export default { VERSION, CATEGORIES, RULES, scan, redact, restore, restoreReport, entropy };
