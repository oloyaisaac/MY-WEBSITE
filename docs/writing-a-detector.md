# Writing a detector

The harness only needs one function. A detector is any ES module whose default export looks like this:

```js
export default {
  name: 'my-detector 1.0',
  detect(text) {
    // return every span of text that should be redacted
    return [{ start: 10, end: 34, type: 'email' }];
  },
};
```

- `start` / `end` are **character offsets** into the exact string you were given (not bytes, not lines).
- `end` is exclusive, like `String.prototype.slice`.
- `type` is a free-form label; it is not scored, it only shows up in failure reports.
- Spans may overlap or come back unsorted — the harness clamps, drops empty spans and sorts.

Then:

```bash
node bench/run.mjs --detector ./my-detector.mjs
node bench/run.mjs --detector ./my-detector.mjs --verbose
node bench/run.mjs --detector ./my-detector.mjs --json > result.json
```

## Reference: the standin adapter

```js
import { scan } from '../../src/standin.js';

export default {
  name: 'standin',
  detect(text) {
    return scan(text).findings.map((f) => ({ start: f.start, end: f.end, type: f.ruleId }));
  },
};
```

## Wrapping a Python detector (spaCy, Presidio, scrubadub…)

Keep the process boundary boring: one JSON object per line in, one out.

`detector.py`

```python
import json, sys
from presidio_analyzer import AnalyzerEngine

engine = AnalyzerEngine()

for line in sys.stdin:
    text = json.loads(line)["text"]
    hits = engine.analyze(text=text, language="en")
    print(json.dumps([{"start": h.start, "end": h.end, "type": h.entity_type} for h in hits]), flush=True)
```

`presidio-adapter.mjs`

```js
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

const child = spawn('python3', ['detector.py'], { stdio: ['pipe', 'pipe', 'inherit'] });
const pending = [];
createInterface({ input: child.stdout }).on('line', (line) => pending.shift()?.(JSON.parse(line)));

export default {
  name: 'presidio',
  detect(text) {
    // the harness is synchronous; pre-compute results for the corpus texts
    const hit = cache.get(text) ?? [];
    return hit;
  },
};
```

Because `detect()` is synchronous, pre-compute the corpus first:

```bash
node -e '
  const { loadCorpus } = await import("./bench/lib.mjs");
  const fs = await import("node:fs");
  fs.writeFileSync("texts.jsonl", loadCorpus().map(c => JSON.stringify({ id: c.id, text: c.text })).join("\n"));
' --input-type=module
```

…then have your adapter read a sidecar `results.json` keyed by case id. A small `--async` mode is on the roadmap;
if you need it now, a `detect()` that blocks on `Atomics.wait` over a worker thread works surprisingly well.

## What to expect from the numbers

- Run `--verbose` first. The failure list is the useful part; the percentages are the summary.
- A detector that gets **recall** but not **negative specificity** is a compliance incident waiting to happen: it
  will redact the technical text people actually paste.
- Compare against `bench/adapters/naive.mjs` to see what "looks reasonable, is not" scores like.
- Never tune on the `test` split. Add cases to `dev`, fix, re-run; keep the held-out set blind.
