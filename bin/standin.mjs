#!/usr/bin/env node
/**
 * standin — CLI.
 *
 *   standin ticket.txt                    scrub to stdout
 *   standin ticket.txt --vault v.json     scrub, save the mapping
 *   standin reply.md --restore v.json     put the real values back
 *   git diff | standin                    scrub stdin
 *   standin notes.md --check              exit 1 if anything was found
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { scan, restore, VERSION } from '../src/standin.js';

const HELP = `standin — reversible redaction for text you hand to an LLM

Usage
  standin [files...] [options]        scrub files (or stdin) to stdout
  standin reply.md --restore v.json   put original values back into a reply

Options
  --vault <file>        write the placeholder mapping to <file> (JSON)
  --restore <file>      read a vault and restore placeholders
  --json                print the full scan result as JSON
  --check               exit 1 if anything sensitive was found (CI friendly)
  --in-place            overwrite each input file with the scrubbed text
  --mask brace          use {{EMAIL_1}} instead of [EMAIL_1]
  --experimental        include names & addresses (approximate)
  --categories <list>   comma separated: secrets,finance,identity,contact,network,people
  --quiet               suppress the summary on stderr
  -h, --help            show this help
  -v, --version         print version
`;

function parseArgs(argv) {
  const args = { files: [], mask: 'bracket', categories: null, experimental: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h':
      case '--help':
        args.help = true;
        break;
      case '-v':
      case '--version':
        args.version = true;
        break;
      case '--vault':
        args.vault = argv[++i];
        break;
      case '--restore':
        args.restore = argv[++i];
        break;
      case '--json':
        args.json = true;
        break;
      case '--check':
        args.check = true;
        break;
      case '--in-place':
        args.inPlace = true;
        break;
      case '--quiet':
        args.quiet = true;
        break;
      case '--experimental':
        args.experimental = true;
        break;
      case '--mask':
        args.mask = argv[++i] === 'brace' ? 'brace' : 'bracket';
        break;
      case '--categories':
        args.categories = String(argv[++i] || '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
        break;
      default:
        if (a.startsWith('-') && a !== '-') {
          process.stderr.write(`standin: unknown option ${a}\n`);
          process.exit(2);
        }
        args.files.push(a);
    }
  }
  return args;
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

const args = parseArgs(process.argv.slice(2));

if (args.help) {
  process.stdout.write(HELP);
  process.exit(0);
}
if (args.version) {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  process.stdout.write(`${pkg.version}\n`);
  process.exit(0);
}

const readInputs = async () => {
  const files = args.files.filter((f) => f !== '-');
  if (!files.length) return [{ name: '<stdin>', text: await readStdin() }];
  return files.map((f) => ({ name: f, text: readFileSync(f, 'utf8') }));
};

/** Keep placeholders stable across several input files. */
let sharedVault = [];

try {
  const inputs = await readInputs();

  if (args.restore) {
    const payload = JSON.parse(readFileSync(args.restore, 'utf8'));
    const vault = Array.isArray(payload) ? payload : payload.vault || [];
    let count = 0;
    for (const input of inputs) {
      const out = restore(input.text, vault);
      if (args.inPlace && input.name !== '<stdin>') writeFileSync(input.name, out);
      else process.stdout.write(out);
      count += out !== input.text ? 1 : 0;
    }
    if (!args.quiet) process.stderr.write(`standin: restored placeholders in ${count} input(s)\n`);
    process.exit(0);
  }

  let found = 0;
  const results = [];

  for (const input of inputs) {
    const result = scan(input.text, {
      mask: args.mask,
      experimental: args.experimental,
      categories: args.categories,
      vault: sharedVault,
    });
    sharedVault = result.vault;
    found += result.total;
    results.push({ name: input.name, result });

    if (args.inPlace && input.name !== '<stdin>') writeFileSync(input.name, result.redacted);
    else if (!args.json) process.stdout.write(result.redacted);
  }

  if (args.json) {
    process.stdout.write(
      JSON.stringify(
        {
          version: VERSION,
          files: results.map(({ name, result }) => ({
            name,
            total: result.total,
            severity: result.severityCount,
            byCategory: result.byCategory,
            findings: result.findings.map((f) => ({
              rule: f.ruleId,
              label: f.label,
              category: f.category,
              severity: f.severity,
              placeholder: f.placeholder,
              start: f.start,
              end: f.end,
            })),
            redacted: result.redacted,
            vault: result.vault,
          })),
        },
        null,
        2
      ) + '\n'
    );
  }

  if (args.vault) {
    writeFileSync(
      args.vault,
      JSON.stringify(
        {
          tool: 'standin',
          version: VERSION,
          createdAt: new Date().toISOString(),
          note: 'Keep this file private. It maps placeholders back to the original values.',
          vault: sharedVault,
        },
        null,
        2
      ) + '\n',
      { mode: 0o600 }
    );
  }

  if (!args.quiet) {
    const counts = sharedVault.reduce((acc, e) => ({ ...acc, [e.category]: (acc[e.category] || 0) + 1 }), {});
    const summary = Object.entries(counts)
      .map(([k, v]) => `${v} ${k}`)
      .join(', ');
    process.stderr.write(
      found
        ? `standin: replaced ${found} placeholder(s)${summary ? ` — ${summary}` : ''}${args.vault ? `, vault in ${args.vault}` : ''}\n`
        : 'standin: nothing sensitive found\n'
    );
  }

  if (args.check && found > 0) process.exit(1);
} catch (err) {
  process.stderr.write(`standin: ${err.message}\n`);
  process.exit(2);
}
