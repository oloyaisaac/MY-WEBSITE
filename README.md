# standin

**An open benchmark for sensitive-data detection in text — with a zero-dependency redactor that scores on it.**

Every redaction tool is "99% accurate" on a test set it chose itself. There is no public, adversarial corpus that
asks the awkward questions: does it check the Luhn digit, or just count to sixteen? Does it redact the git SHA,
the order number, the Docker digest? standin is that corpus — 198 reviewed cases, 46 of them hard negatives — plus
a harness that scores *any* detector against it, plus a reference implementation you can read in one sitting.

```bash
npm run bench                                        # score the reference implementation
node bench/run.mjs --detector ./my-detector.mjs -v    # score yours
```

No dependencies. No build step. Node 18+.

---

## The problem this measures

A pattern that matches sixteen digits catches every card number — and every order id, tracking number, timestamp
fragment and Luhn-invalid account number it meets. The difference between a redactor you can paste a log into and
one you cannot is not more regex; it is **validation**: Luhn for cards, mod-97 for IBANs, entropy plus context for
keys, and an explicit list of things that must *not* be touched.

That is measurable, and almost nobody measures it. On this corpus:

| detector | precision | recall | exact span | hard-negative specificity |
| --- | ---: | ---: | ---: | ---: |
| `naive-regex` — patterns only, no checksums | 77.2% | 67.3% | 68.6% | 82.3% |
| `standin` — checksums, entropy, context | **98.7%** | **99.4%** | **91.0%** | **97.5%** |

The naive detector is a fair stand-in for most hand-rolled redactors. It gets one in five hard negatives wrong.
That gap is the entire argument for this repository.

## What is in the corpus

| slice | what it holds | cases |
| --- | --- | ---: |
| `contact` | emails, phone numbers in E.164 / national / spaced / punctuated forms | 36 |
| `secrets` | AWS, GitHub, Slack, Google, Stripe, OpenAI/Anthropic keys, JWTs, PEM blocks, credentialed URLs, `password=` pairs, high-entropy blobs | 39 |
| `finance` | Luhn-verified cards (Visa, MC, Amex, Discover, JCB, Diners), mod-97-verified IBANs, BTC/ETH addresses | 30 |
| `identity` | US SSNs and EINs, plus the invalid ranges that must be ignored | 14 |
| `network` | IPv4, IPv6, MAC, URLs carrying tokens or signatures | 20 |
| `mixed` | whole documents — support tickets, nginx logs, CSV exports, YAML, git diffs, JSON responses, invoices, a Swahili chat | 13 |
| `none` | **hard negatives** — git SHAs, UUIDs, hashes, base64 data URIs, Docker digests, version strings, cron, coordinates, code, prose | 46 |

198 cases · 156 marked spans · 10 further cases in `corpus/ambiguous.jsonl` that are deliberately **not** scored.

A case is one line of JSON, reviewed in a diff like code:

```json
{"id":"card/amex-15","cat":"finance","text":"amex 378282246310005 is the corporate card","expect":["378282246310005"]}
{"id":"neg/luhn-invalid-card","cat":"finance","text":"the tracking number 4111111111111112 is on the parcel","expect":[]}
```

Every string in `expect` must occur exactly once in `text`, so a case cannot silently drift when it is edited.
`npm test` enforces that before anything is scored.

## Scores, honestly

The reference implementation was developed against the **dev** split, so its dev score says nothing. The honest
number comes from `corpus/heldout.jsonl`: 30 cases written after the engine was finished, scored once, and never
tuned against.

| split | cases | spans | precision | recall | exact |
| --- | ---: | ---: | ---: | ---: | ---: |
| dev — used for tuning | 168 | 136 | 100.0% | 100.0% | 89.7% |
| **test — written blind, scored once** | **30** | **20** | **90.5%** | **95.0%** | **100%** |

Twenty spans is a small sample; one miss moves recall by five points. Its three mistakes are documented and
deliberately left unfixed — see [Known misses](#known-misses).

## Score your own detector

A detector is any ES module exporting `detect(text) -> [{start, end, type?}]`:

```js
// my-detector.mjs
export default {
  name: 'my-detector 1.0',
  detect(text) {
    return [{ start: 10, end: 34, type: 'email' }];
  },
};
```

```bash
node bench/run.mjs --detector ./my-detector.mjs --verbose
node bench/run.mjs --detector ./my-detector.mjs --json > result.json
```

Wrapping Presidio, spaCy or scrubadub takes an adapter and a sidecar file; the recipe is in
[docs/writing-a-detector.md](./docs/writing-a-detector.md).

```
detector  standin 0.2.0
corpus    198 cases · 156 marked spans · 46 hard-negative cases

category        cases   spans   TP     FP     FN     precision   recall    exact
──────────────  ──────  ──────  ─────  ─────  ─────  ──────────  ────────  ───────
contact          36      32      31     0      1      100.0%      96.9%     93.5%
finance          30      24      24     0      0      100.0%      100.0%    100.0%
secrets          39      36      36     0      0      100.0%      100.0%    86.1%
…
overall          198     156     155     2      1   98.7%        99.4%     91.0%

exact-span   91.0%   (findings that matched a marked span character for character)
over-reach   1.2%    (extra characters redacted beyond the marked spans)
negatives    97.5%   (hard-negative cases with no false positive)
```

## Metric definitions, in one table

| metric | meaning |
| --- | --- |
| **precision** | matched findings ÷ all findings — punishes over-redaction |
| **recall** | matched marked spans ÷ all marked spans — punishes leaks |
| **exact span** | findings that equal a marked span character for character — punishes sloppy boundaries |
| **over-reach** | characters redacted outside marked spans ÷ characters marked — punishes "remove everything" |
| **negative specificity** | hard-negative cases with zero findings — punishes redacting technical text |

Matching is overlap-based, because redaction has no single correct boundary; exactness is reported separately
rather than baked into the pass/fail. Full reasoning, including why the ambiguous set exists and what the corpus
cannot measure: [docs/methodology.md](./docs/methodology.md).

## The reference implementation

`src/standin.js` is the baseline every detector is compared to — 28 rules, no dependencies, and it does the
unglamorous parts: Luhn, mod-97, entropy with context guards, hash and object-id exclusion, overlap precedence,
and a stable mapping so the same value always gets the same placeholder.

```js
import { redact, restore } from './src/standin.js';

const { text, vault } = redact('card 4111 1111 1111 1111, email a@b.co');
// text  → 'card [CARD_1], email [EMAIL_1]'

restore('I charged [CARD_1] and emailed [EMAIL_1].', vault);
// → 'I charged 4111 1111 1111 1111 and emailed a@b.co.'
```

It is reversible because that is what makes a redactor usable with a model: you scrub, the model answers about
`[EMAIL_1]`, and you put the real values back on your own machine. The CLI does the same thing:

```bash
node bin/standin.mjs examples/sample.txt --vault vault.json   # scrub, keep the mapping
node bin/standin.mjs reply.md --restore vault.json            # put the values back
git diff | node bin/standin.mjs --check                       # exit 1 if anything was found
```

Typing `[EMAIL_1]` back in is not the interesting part. Being *measurable* is.

## Known misses

Held-out, unfixed on purpose — fixing them against the test split would just make it a second tuning set.

| case | what happened | why it is hard |
| --- | --- | --- |
| `held/phone-uk-mobile` | `07700 900123` missed | 5+6 grouping with a leading 0 needs a locale-aware pattern |
| `held/neg-doi` | `182.2024.4471` flagged as a phone | dots separate both phone numbers and DOIs |
| `held/neg-git-ssh-remote` | `git@github.com` flagged as an email | syntactically an email, semantically a public remote |

## What this is not

- **Not a compliance product.** Span-level detection is not anonymisation; the remaining text can still identify
  someone by combination.
- **Not complete.** Two hundred short cases cannot cover every key format or national ID — that is a backlog, not
  a claim.
- **Not multilingual yet.** Mostly English, a few Swahili and French cases. Nothing here proves anything about
  Arabic, Devanagari, or CJK text.
- **Not independent.** The corpus author also wrote the reference implementation, which is exactly why the
  held-out split and the "add cases, not code" contribution rule exist.

## Repo layout

```
corpus/            198 scored cases (JSONL) + 10 ambiguous ones
bench/run.mjs      CLI harness: table, --json, --markdown, CI gates
bench/lib.mjs      loader, validator, scorer, formatters
bench/adapters/    standin.mjs (reference), naive.mjs (baseline to beat)
src/standin.js     reference implementation: scan / redact / restore
bin/standin.mjs    CLI
test/              31 tests: engine behaviour, corpus integrity, regression gates
docs/              methodology, writing a detector
```

## Contributing

The most valuable pull request adds a **case**, not code — especially a format nobody handles yet, or a hard
negative that trips a naive matcher. See [CONTRIBUTING.md](./CONTRIBUTING.md).

```bash
npm test    # engine + corpus integrity, no install required
npm run bench
```

## License

- **Code** — MIT, see [LICENSE](./LICENSE).
- **Corpus** — CC0 1.0, see [corpus/LICENSE](./corpus/LICENSE). Publish it, mirror it, train on it, embed it in your
  own benchmark; no permission needed.

All identifiers in the corpus are synthetic.
