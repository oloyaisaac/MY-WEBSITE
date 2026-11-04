# standin

**Reversible redaction for text you hand to an LLM.**

Paste a support ticket, a log line, an invoice, a `.env` file. standin swaps the sensitive parts for stable
placeholders (`[EMAIL_1]`, `[CARD_2]`, `[AWS_KEY_1]`) — you paste the safe version into ChatGPT, Claude or Gemini —
then standin puts the real values back into the reply.

Everything runs on your device. No server, no API key, no analytics, no build step, zero dependencies.

```
   you paste                          the model sees                    you get back
   ─────────                          ──────────────                    ────────────
   charge 4111 1111 1111 1111    →    charge [CARD_1]        →          charge •••• 1111
   email a.mensah@acme.co.ug          email [EMAIL_1]                   email a.mensah@acme.co.ug
```

- **Web app:** open `index.html` (or `npm run dev` → http://localhost:3000)
- **Library:** `import { redact, restore } from './src/standin.js'`
- **CLI:** `npx standin ticket.txt --vault vault.json` / `standin reply.md --restore vault.json`
- **License:** MIT

---

## Why reversible?

Most redaction tools are one-way. That breaks the moment you use them for actual work:

1. You scrub a customer email so the model can't see who it is.
2. You ask "draft a reply".
3. The model answers about `[EMAIL_1]`, and you are back to hand-copying values out of a spreadsheet.

standin keeps the mapping in a **vault** you own (a plain JSON object, held in memory in the browser, never
uploaded). Same value → same placeholder, so the model can still reason about "the same customer" across a long
thread. New values get new numbers; existing ones never shift.

## What it finds

| Group | Detectors |
| --- | --- |
| **Secrets** | private key blocks (PEM), JWTs, OpenAI/Anthropic (`sk-…`), AWS access keys + secret keys, GitHub tokens, Slack tokens, Google API keys, Stripe keys, bearer tokens, URLs with embedded credentials, `password=`/`api_key:` style pairs, high-entropy strings with context checks |
| **Financial** | payment cards (**Luhn verified**), IBANs (**mod-97 verified**), BTC and ETH wallet addresses |
| **Identity** | US SSNs, EINs |
| **Contact** | email addresses, phone numbers (rejects dates, years, IPv4, card-shaped digit groups) |
| **Network** | IPv4/IPv6, MAC addresses, URLs carrying `token=`, `key=`, `sig=` … |
| **People** *(opt-in)* | street addresses, names in contexts like `Regards, …`, `Dr …`, `my name is …` |

Checksums are enforced, not guessed: a 16-digit number that fails Luhn is **not** a card, and an IBAN that fails
mod-97 is **not** an IBAN. That is what keeps the false-positive rate low enough to be usable.

## Use it in 30 seconds

### Browser

```bash
git clone https://github.com/oloyaisaac/MY-WEBSITE
cd MY-WEBSITE
npm run dev     # or just open index.html — there is nothing to build
```

Paste text → copy the scrubbed version → ask your model → paste its answer in the **Restore reply** tab.

### Library

```js
import { redact, restore } from './src/standin.js';

const { text, vault } = redact('card 4111 1111 1111 1111, email a@b.co');
// text  → 'card [CARD_1], email [EMAIL_1]'
// vault → [{ placeholder: '[CARD_1]', value: '4111 1111 1111 1111', … }]

const answer = 'I charged [CARD_1] and emailed [EMAIL_1].';
restore(answer, vault);
// → 'I charged 4111 1111 1111 1111 and emailed a@b.co.'
```

Options: `categories` (limit detectors), `experimental` (names & addresses), `mask` (`bracket` | `brace`), `vault`
(seed with an existing vault so placeholders stay stable across chunks).

### CLI

```bash
npx standin ticket.txt                     # scrub to stdout
npx standin ticket.txt --vault vault.json  # scrub + save mapping
npx standin reply.md --restore vault.json  # put values back
git diff | npx standin                     # scrub stdin
npx standin notes.md --check               # exit 1 if anything was found (CI)
npx standin notes.md --in-place --quiet    # rewrite the file
```

`--json` gives a machine-readable report with rule ids, severities and offsets.

## Design notes

- **Precedence with overlap resolution.** Rules are ordered most-specific first. A PEM block beats the generic
  high-entropy rule that would otherwise match fragments inside it; a card number beats the phone-number rule.
- **Stable placeholders.** The vault is keyed by value, so repeating a value never creates a second placeholder.
- **Idempotent.** Scrubbing already-scrubbed text changes nothing — placeholders are recognised as placeholders.
- **Tolerant restore.** If a model strips the brackets and writes `EMAIL_1`, restore still works.
- **No network primitives anywhere.** The app imports one module from the same origin and touches no other URL.

## Honest limitations

- This is a careful pattern-and-checksum filter, **not** a compliance product. It can miss context-dependent
  identifiers (an unlabelled name, an unusual national ID format) and it can over-redact.
- Names and addresses need language understanding. They are heuristic, opt-in, and will miss things.
- The vault is as sensitive as the data you removed. In the browser it lives in memory only; from the CLI it is
  written with `0600` permissions. Don't commit it.
- Placeholders leak *shape*: the model knows there was a card number and roughly where.

## Roadmap

- [ ] Passphrase-encrypted vault export (AES-GCM via WebCrypto) so a vault can be safely stored between sessions
- [ ] Custom user rules (regex + label) that survive reload in a local rules file
- [ ] Streaming mode for large files
- [ ] `--watch` for log tails
- [ ] Optional NER pass (local ONNX model) for names, for those who want it and accept the download

## Contributing

Bug reports with a failing example are the most useful thing you can send. Add a case to
`test/standin.test.js` first — a redaction tool is only as good as its false-positive and false-negative suite.

```bash
npm test   # node --test, no install needed
```

## License

MIT — see [LICENSE](./LICENSE). Use it commercially, fork it, ship it. Attribution is nice, not required.

All sample data in this repository (including the one loaded by the "Load sample" button) is synthetic.
