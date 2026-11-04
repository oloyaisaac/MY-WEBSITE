# Contributing

The most useful contribution is a **case**, not code. Two hundred cases is a small corpus, and whole families of
identifiers are missing.

## Add a case

1. Append one JSON line to the right file in `corpus/` (`contact`, `finance`, `secrets`, `identity`, `network`,
   `mixed`, `hard-negatives`, or `ambiguous`).
2. Every string in `expect` must appear **exactly once** in `text`.
3. Use invented data only. Never commit real personal data, real keys, or a real card number — including in a
   "realistic" example.
4. Run `npm test` (validates the corpus) and `npm run bench` (shows the effect).

If a case needs a credential that looks real, store it as a **fixture** split into fragments — GitHub push
protection blocks whole key-shaped strings, and it is right to. See
[docs/methodology.md](./docs/methodology.md#fixtures-key-shaped-values-without-triggering-secret-scanning).

```json
{"id":"email/with-country-tld","cat":"contact","text":"write to grace@acme.co.ug","expect":["grace@acme.co.ug"]}
```

Good cases are one of:

- **a format nobody handles yet** — a regional phone shape, a cloud key, a national ID;
- **a hard negative** — text stuffed with numbers and hex that must *not* be redacted;
- **a realistic document** — a whole ticket, log excerpt or config file in `mixed`, because real leaks are messy.

## Add a detector

See [docs/writing-a-detector.md](./docs/writing-a-detector.md). Detectors live outside the harness; an adapter is
~10 lines. If your detector exposes a public score, say which split and corpus version it refers to.

## Rules of the benchmark

- Do not edit a case to make a detector pass. If the case is wrong, say why in the pull request.
- Do not tune against `corpus/heldout.jsonl`. Fixes go to the dev split; the held-out set is rotated, not patched.
- Fixing a *reference implementation* miss is welcome — add the case to dev first, then the fix, then the test.
- Keep the corpus human-reviewable: one case per line, stable ids, no generated megabytes.

## Code

```bash
npm test        # unit tests + corpus validation, no dependencies, no install
npm run bench   # score the reference implementation
```

Node 18+. No build step, no dependencies. Please keep it that way — the engine is meant to be auditable in one
sitting.
