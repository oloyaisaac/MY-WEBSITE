#!/usr/bin/env node
/**
 * standin benchmark harness.
 *
 *   node bench/run.mjs                                  score standin
 *   node bench/run.mjs --detector ./my-detector.mjs      score your own detector
 *   node bench/run.mjs --verbose                         list every miss
 *   node bench/run.mjs --markdown                        table for a README
 *   node bench/run.mjs --min-precision 0.95 --min-recall 0.85   CI gate
 */
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { loadCorpus, score, formatTable, formatMarkdown, formatFailures } from './lib.mjs';

const argv = process.argv.slice(2);
const has = (flag) => argv.includes(flag);
const val = (flag, fallback) => {
  const i = argv.indexOf(flag);
  return i === -1 ? fallback : argv[i + 1];
};

if (has('-h') || has('--help')) {
  process.stdout.write(`standin benchmark

Usage
  node bench/run.mjs [options]

Options
  --detector <path>     module exporting detect(text) -> [{start, end, type}]  (default: bench/adapters/standin.mjs)
  --include-ambiguous   also score corpus/ambiguous.jsonl (off by default: those cases have no defensible answer)
  --split <dev|test|all>  score the tuning split, the held-out split, or both (default: all)
  --category <name>     only score one corpus slice
  --verbose, -v         print each false positive and false negative
  --json                machine readable result on stdout
  --markdown            markdown table on stdout (for docs)
  --min-precision <n>   exit 1 if precision is lower (CI gate)
  --min-recall <n>      exit 1 if recall is lower (CI gate)
  --no-banner           omit the header lines
`);
  process.exit(0);
}

const detectorPath = resolve(val('--detector', new URL('./adapters/standin.mjs', import.meta.url).pathname));
const includeAmbiguous = has('--include-ambiguous');
const category = val('--category', null);
const split = val('--split', 'all');
const minPrecision = val('--min-precision', null);
const minRecall = val('--min-recall', null);

const loaded = await import(pathToFileURL(detectorPath).href);
const detector = loaded.default ?? loaded;

let cases = loadCorpus({ includeAmbiguous });
if (category) cases = cases.filter((c) => c.cat === category);
if (split !== 'all') cases = cases.filter((c) => c.split === split);
if (!cases.length) {
  process.stderr.write(`no cases matched (category: ${category})\n`);
  process.exit(2);
}

const result = score(detector, cases);
const t = result.totals;

if (has('--json')) {
  process.stdout.write(
    JSON.stringify(
      {
        detector: result.detector,
        corpus: { cases: t.cases, spans: t.spans, includeAmbiguous, split },
        overall: {
          precision: t.precision,
          recall: t.recall,
          f1: t.f1,
          exactRate: t.exactRate,
          overreach: t.overreach,
          negativeSpecificity: t.negativeSpecificity,
          tp: t.tp,
          fp: t.fp,
          fn: t.fn,
        },
        byCategory: result.byCategory,
        failures: result.failures,
      },
      null,
      2
    ) + '\n'
  );
} else if (has('--markdown')) {
  process.stdout.write(formatMarkdown(result) + '\n');
} else {
  if (!has('--no-banner')) {
    process.stdout.write(`detector  ${result.detector}\n`);
    process.stdout.write(
      `corpus    ${t.cases} ${split === 'all' ? '' : `${split}-split `}cases · ${t.spans} marked spans · ${t.negotives} hard-negative cases`
    );
    process.stdout.write(includeAmbiguous ? ' · including ambiguous\n\n' : '\n\n');
  }
  process.stdout.write(formatTable(result) + '\n\n');
  process.stdout.write(
    `exact-span   ${(t.exactRate * 100).toFixed(1)}%   (findings that matched a marked span character for character)\n`
  );
  process.stdout.write(
    `over-reach   ${(t.overreach * 100).toFixed(1)}%   (extra characters redacted beyond the marked spans)\n`
  );
  process.stdout.write(
    `negatives    ${(t.negativeSpecificity * 100).toFixed(1)}%   (hard-negative cases with no false positive)\n`
  );

  if (result.failures.length) {
    process.stdout.write(`\n${result.failures.length} mistake(s)\n`);
    if (has('--verbose') || has('-v')) process.stdout.write(formatFailures(result) + '\n');
    else process.stdout.write('  re-run with --verbose to see them\n');
  } else {
    process.stdout.write('\nno mistakes\n');
  }
}

const gates = [];
if (minPrecision != null && t.precision < Number(minPrecision)) gates.push(`precision ${(t.precision * 100).toFixed(1)}% < ${minPrecision}`);
if (minRecall != null && t.recall < Number(minRecall)) gates.push(`recall ${(t.recall * 100).toFixed(1)}% < ${minRecall}`);
if (gates.length) {
  process.stderr.write(`\ngate failed: ${gates.join(', ')}\n`);
  process.exit(1);
}
