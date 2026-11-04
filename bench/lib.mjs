/**
 * Benchmark core: load cases, score a detector, format results.
 * No dependencies. The corpus is plain JSONL so it stays reviewable in a diff.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export const CORPUS_DIR = new URL('../corpus/', import.meta.url).pathname;

const MAX_SHOWN = 90;

/** Load and validate every case in the corpus directory. */
export function loadCorpus({ dir = CORPUS_DIR, includeAmbiguous = false } = {}) {
  const files = readdirSync(dir)
    .filter((f) => f.endsWith('.jsonl'))
    .filter((f) => includeAmbiguous || f !== 'ambiguous.jsonl')
    .sort();

  const cases = [];
  const problems = [];

  for (const file of files) {
    const lines = readFileSync(join(dir, file), 'utf8').split('\n');
    lines.forEach((line, i) => {
      if (!line.trim() || line.trim().startsWith('//')) return;
      const where = `${file}:${i + 1}`;
      let raw;
      try {
        raw = JSON.parse(line);
      } catch (err) {
        problems.push(`${where} is not valid JSON (${err.message})`);
        return;
      }
      try {
        cases.push(normalize(raw, where, file));
      } catch (err) {
        problems.push(`${where} ${err.message}`);
      }
    });
  }

  if (problems.length) {
    const err = new Error(`corpus is invalid:\n  ${problems.join('\n  ')}`);
    err.problems = problems;
    throw err;
  }
  if (!cases.length) throw new Error(`no cases found in ${dir}`);

  const ids = new Set();
  for (const c of cases) {
    if (ids.has(c.id)) throw new Error(`duplicate case id: ${c.id}`);
    ids.add(c.id);
  }

  return cases;
}

/**
 * Fixtures let a case describe a key-shaped value without storing it whole:
 *
 *   "fixtures": {"SLACK": ["xoxb-123456789012-", "1234567890123-AbCdEf"]}
 *   "text": "SLACK_TOKEN={{SLACK}}"
 *
 * Fragments are joined before scoring, so detectors see the real shape while
 * repository secret scanning (correctly) sees nothing to quarantine.
 */
function expandFixtures(raw) {
  const fixtures = raw.fixtures && typeof raw.fixtures === 'object' ? raw.fixtures : {};
  const resolved = {};
  for (const [name, value] of Object.entries(fixtures)) {
    resolved[name] = Array.isArray(value) ? value.join('') : String(value);
  }
  const apply = (text) =>
    text.replace(/\{\{([A-Z0-9_]+)\}\}/g, (whole, name) => {
      if (!(name in resolved)) throw new Error(`case ${raw.id}: unknown fixture {{${name}}}`);
      return resolved[name];
    });

  const text = apply(raw.text);
  const expect = (raw.expect ?? []).map((entry) =>
    typeof entry === 'string'
      ? apply(entry)
      : { ...entry, v: entry?.v == null ? entry?.v : apply(entry.v) }
  );
  return { ...raw, text, expect };
}

function normalize(input, where, file) {
  const raw = expandFixtures(input);
  if (!raw.id || typeof raw.id !== 'string') throw new Error('missing string "id"');
  if (typeof raw.text !== 'string' || !raw.text.length) throw new Error(`case ${raw.id} has no text`);
  const expect = raw.expect ?? [];
  if (!Array.isArray(expect)) throw new Error(`case ${raw.id}: "expect" must be an array`);

  const spans = expect.map((entry) => {
    const value = typeof entry === 'string' ? entry : entry?.v;
    const type = typeof entry === 'string' ? undefined : entry?.t;
    if (typeof value !== 'string' || !value.length) {
      throw new Error(`case ${raw.id}: expectation must be a string or {v, t}`);
    }
    const first = raw.text.indexOf(value);
    if (first === -1) throw new Error(`case ${raw.id}: "${clip(value)}" does not appear in the text`);
    if (raw.text.indexOf(value, first + 1) !== -1) {
      throw new Error(`case ${raw.id}: "${clip(value)}" appears more than once — make it unique`);
    }
    return { start: first, end: first + value.length, value, type };
  });

  return {
    id: raw.id,
    cat: raw.cat || 'none',
    text: raw.text,
    expect: spans,
    note: raw.note,
    file,
    split: raw.split === 'test' ? 'test' : 'dev',
    ambiguous: file === 'ambiguous.jsonl',
    tags: raw.tags || [],
  };
}

const clip = (s) => (s.length > MAX_SHOWN ? `${s.slice(0, MAX_SHOWN)}…` : s);

/** Run a detector and return clean, sorted spans inside the text. */
export function runDetector(detector, text) {
  if (!detector || typeof detector.detect !== 'function') {
    throw new TypeError('detector must expose detect(text) -> [{start, end}]');
  }
  const raw = detector.detect(text) ?? [];
  const spans = [];
  for (const s of raw) {
    const start = Math.max(0, Math.min(text.length, Number(s.start)));
    const end = Math.max(0, Math.min(text.length, Number(s.end)));
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) continue;
    spans.push({ start, end, start0: start, type: s.type, severity: s.severity });
  }
  spans.sort((a, b) => a.start - b.start || a.end - b.end);
  return spans;
}

const overlapLen = (a, b) => Math.max(0, Math.min(a.end, b.end) - Math.max(a.start, b.start));
const isBlank = (text, span) => !text.slice(span.start, span.end).trim();

/** Score one case. */
export function scoreCase(detector, testCase) {
  const findings = runDetector(detector, testCase.text);
  const expected = testCase.expect.map((s) => ({ ...s }));
  const used = new Set();
  const pairs = [];
  let tp = 0;
  let exact = 0;

  for (const span of expected) {
    let best = -1;
    let bestOverlap = 0;
    findings.forEach((finding, i) => {
      if (used.has(i)) return;
      const o = overlapLen(span, finding);
      if (o > bestOverlap) {
        bestOverlap = o;
        best = i;
      }
    });
    if (best === -1) continue;
    used.add(best);
    tp += 1;
    const finding = findings[best];
    if (finding.start === span.start && finding.end === span.end) exact += 1;
    pairs.push({ span, finding });
  }

  const falsePositives = findings.filter((f, i) => !used.has(i) && !isBlank(testCase.text, f));
  const falseNegatives = expected.filter((s) => !pairs.some((p) => p.span.start === s.start));

  // how many characters were redacted outside the marked spans
  let outside = 0;
  for (const f of findings) {
    if (isBlank(testCase.text, f)) continue;
    let covered = 0;
    for (const s of expected) covered += overlapLen(f, s);
    outside += Math.max(0, f.end - f.start - covered);
  }
  const expectedChars = expected.reduce((n, s) => n + (s.end - s.start), 0);

  return {
    case_: testCase,
    findings,
    expected,
    tp,
    exact,
    fp: falsePositives.length,
    fn: falseNegatives.length,
    outside,
    expectedChars,
    failures: [
      ...falsePositives.map((f) => ({
        kind: 'false-positive',
        value: clip(testCase.text.slice(f.start, f.end)),
        start: f.start,
        end: f.end,
      })),
      ...falseNegatives.map((s) => ({ kind: 'false-negative', value: clip(s.value), start: s.start, end: s.end })),
    ],
  };
}

/** Score the whole corpus. */
export function score(detector, cases) {
  const results = cases.map((c) => ({ ...scoreCase(detector, c), cat: c.cat, file: c.file }));
  const totals = results.reduce(
    (acc, r) => {
      acc.tp += r.tp;
      acc.exact += r.exact;
      acc.fp += r.fp;
      acc.fn += r.fn;
      acc.outside += r.outside;
      acc.expectedChars += r.expectedChars;
      acc.spans += r.expected.length;
      acc.cases += 1;
      if (!r.expected.length && r.fp === 0) acc.cleanNegatives += 1;
      if (!r.expected.length) acc.negotives += 1;
      return acc;
    },
    { cases: 0, spans: 0, tp: 0, fp: 0, fn: 0, exact: 0, outside: 0, expectedChars: 0, cleanNegatives: 0, negotives: 0 }
  );

  const byCategory = {};
  for (const r of results) {
    const bucket = (byCategory[r.cat] ??= { cases: 0, spans: 0, tp: 0, exact: 0, fp: 0, fn: 0, outside: 0, expectedChars: 0 });
    bucket.cases += 1;
    bucket.spans += r.expected.length;
    bucket.tp += r.tp;
    bucket.exact += r.exact;
    bucket.fp += r.fp;
    bucket.fn += r.fn;
    bucket.outside += r.outside;
    bucket.expectedChars += r.expectedChars;
  }

  const precision = totals.tp + totals.fp ? totals.tp / (totals.tp + totals.fp) : 1;
  const recall = totals.spans ? totals.tp / totals.spans : 1;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;

  return {
    detector: detector.name || 'unnamed',
    results,
    totals: {
      ...totals,
      precision,
      recall,
      f1,
      exactRate: totals.tp ? totals.exact / totals.tp : 1,
      overreach: totals.expectedChars ? totals.outside / totals.expectedChars : 0,
      negativeSpecificity: totals.negotives ? totals.cleanNegatives / totals.negotives : 1,
    },
    byCategory,
    failures: results.flatMap((r) =>
      r.failures.map((f) => ({ case: r.case_.id, cat: r.cat, file: r.file, ...f }))
    ),
  };
}

/* ------------------------------- output ------------------------------- */

const pct = (n) => `${(n * 100).toFixed(1)}%`;
const pad = (s, n) => String(s).padEnd(n);
const lpad = (s, n) => String(s).padStart(n);

export function formatTable(result) {
  const rows = Object.entries(result.byCategory).sort((a, b) => b[1].spans - a[1].spans);
  const head = ['category', 'cases', 'spans', 'TP', 'FP', 'FN', 'precision', 'recall', 'exact'];
  const widths = [14, 6, 6, 5, 5, 5, 10, 8, 7];

  const line = (cells, fn = pad) => cells.map((c, i) => fn(String(c), widths[i])).join('  ');

  const out = [];
  out.push(line(head));
  out.push(widths.map((w) => '─'.repeat(w)).join('  '));
  for (const [cat, b] of rows) {
    const p = b.spans === 0 ? '—' : pct(b.tp + b.fp ? b.tp / (b.tp + b.fp) : 1);
    const r = b.spans ? pct(b.tp / b.spans) : '—';
    const e = b.tp ? pct(b.exact / b.tp) : '—';
    out.push(line([cat, b.cases, b.spans, b.tp, b.fp, b.fn, p, r, e]));
  }
  const t = result.totals;
  out.push(widths.map((w) => '─'.repeat(w)).join('  '));
  out.push(
    line(
      ['overall', t.cases, t.spans, t.tp, t.fp, t.fn, pct(t.precision), pct(t.recall), pct(t.exactRate)],
      (s, i) => (i === 0 ? pad(s, widths[0]) : lpad(s, widths[i]))
    )
  );
  return out.join('\n');
}

export function formatMarkdown(result) {
  const rows = Object.entries(result.byCategory).sort((a, b) => b[1].spans - a[1].spans);
  const t = result.totals;
  const lines = [
    '| slice | cases | spans | TP | FP | FN | precision | recall | exact |',
    '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  ];
  for (const [cat, b] of rows) {
    const p = b.spans === 0 ? '—' : pct(b.tp + b.fp ? b.tp / (b.tp + b.fp) : 1);
    const r = b.spans ? pct(b.tp / b.spans) : '—';
    const e = b.tp ? pct(b.exact / b.tp) : '—';
    lines.push(`| ${cat} | ${b.cases} | ${b.spans} | ${b.tp} | ${b.fp} | ${b.fn} | ${p} | ${r} | ${e} |`);
  }
  lines.push(
    `| **overall** | **${t.cases}** | **${t.spans}** | **${t.tp}** | **${t.fp}** | **${t.fn}** | **${pct(t.precision)}** | **${pct(t.recall)}** | **${pct(t.exactRate)}** |`
  );
  return lines.join('\n');
}

export function formatFailures(result, limit = 40) {
  const lines = [];
  for (const f of result.failures.slice(0, limit)) {
    lines.push(`  ${f.kind === 'false-positive' ? 'FP' : 'FN'}  ${pad(f.case, 28)} ${JSON.stringify(f.value)}`);
  }
  if (result.failures.length > limit) lines.push(`  … ${result.failures.length - limit} more`);
  return lines.join('\n');
}
