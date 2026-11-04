import test from 'node:test';
import assert from 'node:assert/strict';
import { loadCorpus, score, runDetector } from '../bench/lib.mjs';
import standin from '../bench/adapters/standin.mjs';
import naive from '../bench/adapters/naive.mjs';

const cases = loadCorpus();
const dev = cases.filter((c) => c.split === 'dev');
const heldout = cases.filter((c) => c.split === 'test');
const devScore = score(standin, dev);
const heldoutScore = score(standin, heldout);

test('the corpus is well formed', () => {
  assert.ok(cases.length >= 150, `expected at least 150 cases, found ${cases.length}`);
  const ids = new Set(cases.map((c) => c.id));
  assert.equal(ids.size, cases.length, 'case ids must be unique');
  for (const c of cases) {
    for (const span of c.expect) {
      assert.equal(
        c.text.slice(span.start, span.end),
        span.value,
        `case ${c.id}: marked span does not line up with the text`
      );
    }
  }
});

test('the corpus covers every category and keeps a negative slice', () => {
  const cats = new Set(cases.map((c) => c.cat));
  for (const cat of ['contact', 'finance', 'secrets', 'identity', 'network', 'mixed', 'none']) {
    assert.ok(cats.has(cat), `missing corpus slice: ${cat}`);
  }
  const negatives = cases.filter((c) => c.expect.length === 0);
  assert.ok(negatives.length >= 40, `expected at least 40 hard-negative cases, found ${negatives.length}`);
});

test('the ambiguous set is excluded by default and loadable on demand', () => {
  assert.ok(!cases.some((c) => c.ambiguous), 'ambiguous cases must not be scored by default');
  const withAmbiguous = loadCorpus({ includeAmbiguous: true });
  assert.ok(withAmbiguous.length > cases.length);
});

test('a detector that throws on a case fails loudly, it does not pass silently', () => {
  const broken = {
    name: 'broken',
    detect() {
      throw new Error('boom');
    },
  };
  assert.throws(() => runDetector(broken, 'anything'), /boom/);
});

test('standin holds its floor on the tuning split', () => {
  const { precision, recall } = devScore.totals;
  assert.ok(precision >= 0.97, `precision regressed to ${(precision * 100).toFixed(1)}%`);
  assert.ok(recall >= 0.97, `recall regressed to ${(recall * 100).toFixed(1)}%`);
});

test('standin holds its floor on the held-out split', () => {
  const { recall } = heldoutScore.totals;
  assert.ok(recall >= 0.9, `held-out recall regressed to ${(recall * 100).toFixed(1)}%`);
});

test('the benchmark separates a naive detector from a validated one', () => {
  const naiveScore = score(naive, dev);
  assert.ok(
    devScore.totals.recall - naiveScore.totals.recall > 0.1,
    'recall gap between standin and the naive baseline is too small — is the corpus too easy?'
  );
  assert.ok(
    devScore.totals.precision >= naiveScore.totals.precision,
    'the naive baseline should not beat standin on precision'
  );
});

test('every scored case produces a usable failure report', () => {
  for (const r of [...devScore.results, ...heldoutScore.results]) {
    for (const f of r.failures) {
      assert.ok(['false-positive', 'false-negative'].includes(f.kind));
      assert.ok(typeof f.value === 'string' && f.value.length > 0);
    }
  }
});
