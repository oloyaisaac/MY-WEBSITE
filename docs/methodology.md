# Methodology

This document describes how the corpus is built, how a detector is scored, and what the numbers do and do not mean.
If you are going to quote a score from this project, read this first.

## Who is being measured

Anyone can score a redaction tool against the corpus:

```bash
node bench/run.mjs --detector ./my-detector.mjs --verbose
```

The reference implementation (`standin`) is scored the same way as everyone else. It is in the repo because a
benchmark without a working baseline is hard to trust — not because its score is the point.

## Case format

One case per line in `corpus/*.jsonl`:

```json
{"id":"email/plain","cat":"contact","text":"ping me at a.mensah@example.co.ug when you land","expect":["a.mensah@example.co.ug"]}
```

- **`id`** — stable, unique, human-readable. Never renumber; add new ones.
- **`cat`** — the slice: `contact`, `finance`, `secrets`, `identity`, `network`, `mixed`, or `none` for hard negatives.
- **`text`** — the document, exactly as a detector will see it. No preprocessing.
- **`expect`** — the substrings that any honest detector must flag. Each literal must occur exactly once in
  `text`, so a case cannot silently drift when the text is edited.
- **`note`** — optional, required-ish for ambiguous cases: why this is hard.
- **`split`** — `dev` (default) or `test`.

`npm test` validates all of this. A corpus that does not parse is a bug, not a soft failure.

### Fixtures: key-shaped values without triggering secret scanning

Any corpus of credential formats looks exactly like leaked credentials to automated scanning, and GitHub push
protection will block the repository (correctly — that is the feature working). Cases therefore describe
key-shaped values in fragments:

```json
{"id":"slack/bot-token","cat":"secrets","fixtures":{"SLACK":["xoxb-123456789012-","1234567890123-AbCdEf"]},"text":"SLACK_TOKEN={{SLACK}}","expect":["{{SLACK}}"]}
```

The loader joins the fragments and substitutes `{{NAME}}` in both `text` and `expect` *before* scoring, so the
detector sees the real shape while the file on disk contains nothing a scanner should quarantine. `npm test` fails
if a case references a fixture it does not define.

## What counts as the right answer

A case marks the *minimum* text that must be removed. Anything a detector removes that does not overlap a marked
span is a false positive, even if a human might argue it was also sensitive. This keeps scoring mechanical and
reproducible instead of a debate.

Two consequences worth being explicit about:

1. **Redacting a superset is allowed but costs "exact span".** A detector that removes the entire URL
   `https://admin:s3cr3t@staging.acme.co.ug/health` when only `admin:s3cr3t` was marked still counts as a true
   positive, but it does not count as an exact match, and it adds to **over-reach**.
2. **Context is not a free pass.** Some strings are only sensitive in context. Where a string is genuinely
   ambiguous it belongs in `corpus/ambiguous.jsonl`, which is excluded from scoring by default.

### The ambiguous set

Ten cases are quarantined there: a bare 40-character hex string, a MongoDB ObjectId, an unlabelled person's name,
AWS's published example key, the jwt.io demo token, a documentation placeholder address, `1.2.3.4` used as a
version number, nine bare digits, and a twelve-digit reference number. Every one has a defensible answer in both
directions, so scoring them would reward whichever convention the corpus author happened to pick.

They are still useful: run `node bench/run.mjs --include-ambiguous` to see how a detector behaves on genuinely
undecidable input. The reference implementation flags 7 of the 10 — it errs toward over-redaction when a string is
indistinguishable from a secret, which is the right failure mode for a redactor and the wrong one for a linter.

## Metrics

For one case: marked spans are matched one-to-one against findings, greedily by largest overlap.

| Metric | Definition | What it punishes |
| --- | --- | --- |
| **precision** | matched findings ÷ all findings | over-redaction, noise, flagging hashes and version numbers |
| **recall** | matched marked spans ÷ all marked spans | missed identifiers — the failure that actually leaks data |
| **exact span** | findings that equal a marked span character for character ÷ matched spans | lazy superset redaction, sloppy boundaries |
| **over-reach** | characters redacted outside marked spans ÷ characters marked | removing whole documents to be safe |
| **negative specificity** | hard-negative cases with zero findings ÷ all hard-negative cases | redacting technical text that contains no personal data |

Precision and recall are micro-averaged over spans, so a dense support ticket with eight identifiers weighs more
than a one-line case. Category rows are reported for slicing, not to be averaged into a headline number.

### Why overlap and not exact match

Redaction has no single correct boundary. Is `4111 1111 1111 1111` a card, or is `card 4111 1111 1111 1111` the
sensitive unit? Both are defensible. Exact matching would declare one of them wrong and turn the benchmark into a
style guide. Overlap counts detection; exactness is reported separately so the information is not lost.

## The hard-negative slice

46 of 198 cases contain **nothing** that should be redacted. They are the point of the benchmark: a regex that
matches `\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}` scores 100% recall on card numbers and destroys every order number,
tracking number and Luhn-invalid 16-digit id it meets. The negative slice is where naive detectors fall apart:

| detector | precision | recall | negative specificity |
| --- | ---: | ---: | ---: |
| `naive-regex` (patterns only, no checksums) | 77.2% | 67.3% | 82.3% |
| `standin` (checksums, entropy, context) | 98.7% | 99.4% | 97.5% |

That gap is the argument for validating values instead of pattern-matching them, and it is the reason this corpus
exists.

## Splits, and the honesty problem

The reference implementation was developed against the **dev** split. Any detector tuned on a corpus will look
excellent on it, so dev scores are close to meaningless as evidence of quality.

To keep at least one honest number, `corpus/heldout.jsonl` (30 cases) was written **after** the engine was
finished, scored **once**, and left alone. Its three misses are documented below and deliberately **not fixed** —
fixing them against the held-out set would turn it into another tuning set. When the corpus grows, the held-out
split is rotated: the current test cases move to dev, and a fresh batch is written blind.

| split | cases | spans | precision | recall |
| --- | ---: | ---: | ---: | ---: |
| dev (tuning) | 168 | 136 | 100.0% | 100.0% |
| test (written blind, scored once) | 30 | 20 | 90.5% | 95.0% |

The honest headline is the test row, with its sample size in view: 20 spans is small, and one miss moves recall by
five points.

## Known misses (held-out, unfixed)

| case | what happened | why it is hard |
| --- | --- | --- |
| `held/phone-uk-mobile` | `07700 900123` missed | 5+6 digit grouping with a leading 0 — needs a locale-aware pattern rather than a global one |
| `held/neg-doi` | `182.2024.4471` flagged as a phone number | dots as separators are legitimate in both phone numbers and DOIs |
| `held/neg-git-ssh-remote` | `git@github.com` flagged as an email | syntactically an email address, semantically a public remote |

These are exactly the kind of trade-off a benchmark should expose rather than hide.

## Limits of this benchmark

- **Span-level, not semantic.** It measures whether the right characters were removed. It cannot tell you whether
  the remaining text still identifies someone by combination.
- **Synthetic text.** Every identifier is invented. Real corpora are messier, longer, and multilingual in ways 198
  short cases are not.
- **Small.** Two hundred cases cannot cover every key format or national ID. Missing formats are a backlog, not a
  claim of completeness.
- **Written by the author of the reference implementation.** The dev split is therefore biased toward what
  `standin` already does. Contributions that add formats nobody has implemented yet are the most valuable kind.
- **No names, addresses or free-text PII scoring.** Detecting those needs models, not patterns; the reference
  implementation keeps a conservative, opt-in rule set but the corpus does not score it.
- **One language family.** Mostly English, with a few Swahili and French cases. Nothing here proves anything about
  Arabic, Devanagari, or CJK text.

## Citing a score

Please include the corpus version and the split:

> standin 0.2.0, corpus v0.1 (198 cases), held-out split: precision 90.5%, recall 95.0% (n=20 spans).

A number without the split, the case count and the detector version is not a result.
