/* standin — browser shell. No frameworks, no network calls, no storage. */
import { scan, restore, CATEGORIES } from './standin.js';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const SAMPLE = `From: Grace Achieng <grace.achieng@acme-logistics.co.ug>
To: support@acme-logistics.co.ug
Subject: Re: Invoice #4471 — card declined twice
Date: Tue, 4 Nov 2025 09:12:04 +0300

Hi team,

Our card on file keeps getting declined. The number is 4111 1111 1111 1111, exp 08/27,
billing address 12 Kimball Street, Kampala. If it's easier, call me on +256 772 123 456
or reach the finance lead, Daniel Okello, on +256 700 998 811.

The nightly export job started failing after the deploy on 2025-11-02:

  [ERROR] upload rejected for tenant 8842
  [ERROR] host: 10.20.30.41  mac: 00:1A:2B:3C:4D:5E
  [ERROR] POST https://api.acme-logistics.co.ug/v1/upload?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI4ODQyIn0.qX3nT9vKpL2mR8sB4wY6cZ1aD7fG5hJ0kM
  [ERROR] aws_access_key_id = AKIAIOSFODNN7EXAMPLE
  [ERROR] aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  [ERROR] db: postgres://etl:Pr0d%21Passw0rd@db-01.internal:5432/warehouse

IBAN for the refund if the card route fails: GB82 WEST 1234 5698 7654 32.

Thanks,
Grace`;

const state = {
  raw: '',
  mask: 'bracket',
  experimental: false,
  categories: new Set(Object.keys(CATEGORIES).filter((k) => CATEGORIES[k].defaultOn)),
  result: null,
  blur: false,
  tab: 'redacted',
};

const esc = (s) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

let toastTimer;
function toast(msg) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 1900);
}

/* ------------------------------ scanning ------------------------------ */

let pending;
function scheduleScan() {
  clearTimeout(pending);
  pending = setTimeout(runScan, 90);
}

function runScan() {
  state.result = scan(state.raw, {
    mask: state.mask,
    experimental: state.experimental,
    categories: [...state.categories],
  });
  render();
}

/* ------------------------------ rendering ----------------------------- */

function renderRedacted() {
  const out = $('#output');
  const res = state.result;
  if (!res || !state.raw.trim()) {
    out.innerHTML = '<span class="empty">Your scrubbed text lands here.</span>';
    return;
  }
  let html = '';
  let cursor = 0;
  for (const f of res.findings) {
    html += esc(res.source.slice(cursor, f.start));
    html += `<span class="ph sev-${f.severity}" title="${esc(f.label)}">${esc(f.placeholder)}</span>`;
    cursor = f.end;
  }
  html += esc(res.source.slice(cursor));
  out.innerHTML = html || '<span class="empty">Nothing here.</span>';
}

function renderFindings() {
  const wrap = $('#findings');
  const res = state.result;
  if (!res || !res.vault.length) {
    wrap.innerHTML = state.raw.trim()
      ? '<p class="empty pad">Nothing sensitive matched. Read it once yourself — patterns miss context.</p>'
      : '<p class="empty pad">Nothing scanned yet. Paste something on the left — or load the sample.</p>';
    return;
  }
  const occurrences = new Map();
  for (const f of res.findings) occurrences.set(f.placeholder, (occurrences.get(f.placeholder) || 0) + 1);

  wrap.innerHTML = res.vault
    .map((entry) => {
      const n = occurrences.get(entry.placeholder) || 1;
      const shown = state.blur ? '•'.repeat(Math.min(28, Math.max(10, entry.value.length))) : entry.value;
      return `
        <div class="finding sev-${entry.severity}">
          <span class="sev-bar"></span>
          <div class="finding-top">
            <span class="finding-label">${esc(entry.label)}</span>
            ${n > 1 ? `<span class="finding-x">×${n}</span>` : ''}
          </div>
          <div class="finding-val ${state.blur ? 'is-blurred' : ''}" data-real="${esc(entry.value)}" data-shown="${esc(shown)}">${esc(shown)}</div>
          <div><span class="finding-ph">${esc(entry.placeholder)}</span></div>
        </div>`;
    })
    .join('');

  for (const el of wrap.querySelectorAll('.finding-val.is-blurred')) {
    el.addEventListener('click', () => {
      const real = el.dataset.real;
      el.textContent = real;
      el.classList.remove('is-blurred');
    });
  }
}

function renderVault() {
  const list = $('#vault-list');
  const res = state.result;
  $('#vault-count').textContent = String(res ? res.vault.length : 0);
  if (!res || !res.vault.length) {
    list.innerHTML = '<p class="empty pad">No placeholders yet.</p>';
    return;
  }
  list.innerHTML = res.vault
    .map(
      (e) => `
      <div class="vault-row">
        <span class="vault-ph">${esc(e.placeholder)}</span>
        <span class="vault-val ${state.blur ? 'is-blurred' : ''}" data-real="${esc(e.value)}">${esc(e.value)}</span>
      </div>`
    )
    .join('');
  for (const el of list.querySelectorAll('.vault-val.is-blurred')) {
    el.addEventListener('click', () => {
      el.textContent = el.dataset.real;
      el.classList.remove('is-blurred');
    });
  }
}

function renderStats() {
  const res = state.result;
  const n = state.raw.length;
  $('#stat-chars').textContent = `${n.toLocaleString()} char${n === 1 ? '' : 's'}`;
  const total = res ? res.total : 0;
  $('#stat-found').textContent =
    total === 0 ? 'nothing to hide yet' : `${total} value${total === 1 ? '' : 's'} replaced`;
  $('#stat-found').style.color = total ? 'var(--accent)' : '';
  const crit = res ? res.severityCount.critical : 0;
  $('#out-note').textContent = total
    ? `${crit ? `${crit} critical · ` : ''}${total} placeholder${total === 1 ? '' : 's'} inserted · nothing has left this page.`
    : 'Nothing has left this page.';
}

function renderChips() {
  const wrap = $('#cat-chips');
  const res = state.result;
  const counts = res ? res.byCategory : {};
  wrap.innerHTML = Object.entries(CATEGORIES)
    .map(([key, meta]) => {
      const on = state.categories.has(key);
      const n = counts[key] || 0;
      return `<button class="chip ${on ? 'is-on' : ''}" data-cat="${key}" aria-pressed="${on}">${esc(meta.short)}${n ? ` ${n}` : ''}</button>`;
    })
    .join('');
  for (const chip of wrap.querySelectorAll('.chip')) {
    chip.addEventListener('click', () => {
      const key = chip.dataset.cat;
      if (key === 'people') {
        state.experimental = !state.experimental;
        $('#opt-experimental').checked = state.experimental;
        if (state.experimental) state.categories.add('people');
        else state.categories.delete('people');
      } else if (state.categories.has(key)) state.categories.delete(key);
      else state.categories.add(key);
      runScan();
    });
  }
}

function renderRestore() {
  const res = state.result;
  const answer = $('#answer').value;
  const out = $('#restored');
  if (!answer.trim()) {
    out.innerHTML = '<span class="empty">Nothing to restore yet.</span>';
    return;
  }
  const restored = restore(answer, res ? res.vault : []);
  out.textContent = restored;
}

function render() {
  renderRedacted();
  renderFindings();
  renderVault();
  renderStats();
  renderChips();
  renderRestore();
}

/* ------------------------------ actions ------------------------------- */

function setTab(tab) {
  state.tab = tab;
  for (const btn of $$('.seg-btn')) {
    const active = btn.dataset.tab === tab;
    btn.classList.toggle('is-active', active);
    btn.setAttribute('aria-selected', String(active));
  }
  for (const panel of $$('.tab-panel')) {
    panel.classList.toggle('is-active', panel.dataset.panel === tab);
  }
  const titles = { redacted: 'Safe to paste', restore: 'Put the values back', vault: 'The vault' };
  $('#out-title').textContent = titles[tab] || 'Safe to paste';
}

async function copy(text, label) {
  if (!text) return toast('Nothing to copy yet');
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label} copied`);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    toast(`${label} copied`);
  }
}

function download(text, filename, type = 'text/plain') {
  if (!text) return toast('Nothing to download yet');
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('Downloaded');
}

function sampleReply() {
  const vault = state.result?.vault || [];
  if (!vault.length) return toast('Scan something first');
  const who =
    vault.find((e) => e.tag === 'EMAIL')?.placeholder ||
    vault.find((e) => e.category === 'contact')?.placeholder ||
    '[EMAIL_1]';
  const money = vault.find((e) => e.tag === 'CARD' || e.category === 'finance')?.placeholder || '';
  $('#answer').value = `Hi,

Thanks for flagging this. I've updated the billing record for ${who}${money ? ` and re-tokenised the card ending in ${money}` : ''}.
The export failure looks like a rotated credential: the token in the upload URL has expired, so the job needs a fresh
one before the next run. I'd retry tonight at 02:00 and watch the tenant 8842 queue.

Anything else you'd like changed before I send this on?`;
  renderRestore();
  setTab('restore');
}

/* ------------------------------ wiring -------------------------------- */

const input = $('#input');
input.addEventListener('input', () => {
  state.raw = input.value;
  scheduleScan();
});

input.addEventListener('dragover', (e) => e.preventDefault());
input.addEventListener('drop', async (e) => {
  e.preventDefault();
  const file = e.dataTransfer?.files?.[0];
  if (!file) return;
  const text = await file.text();
  input.value = text;
  state.raw = text;
  runScan();
  toast(`${file.name} loaded locally`);
});

$('#btn-sample').addEventListener('click', () => {
  input.value = SAMPLE;
  state.raw = SAMPLE;
  runScan();
  toast('Sample loaded — all data in it is fake');
});

$('#btn-clear').addEventListener('click', () => {
  input.value = '';
  state.raw = '';
  $('#answer').value = '';
  runScan();
  input.focus();
});

$('#opt-mask').addEventListener('change', (e) => {
  state.mask = e.target.value;
  runScan();
});

$('#opt-experimental').addEventListener('change', (e) => {
  state.experimental = e.target.checked;
  if (state.experimental) state.categories.add('people');
  else state.categories.delete('people');
  runScan();
});

for (const btn of $$('.seg-btn')) btn.addEventListener('click', () => setTab(btn.dataset.tab));

$('#btn-copy').addEventListener('click', () => copy(state.result?.redacted || state.raw, 'Scrubbed text'));
$('#btn-download').addEventListener('click', () =>
  download(state.result?.redacted || state.raw, 'standin-redacted.txt')
);

$('#btn-copy-restored').addEventListener('click', () => copy($('#restored').textContent, 'Restored text'));
$('#btn-sample-reply').addEventListener('click', sampleReply);
$('#answer').addEventListener('input', renderRestore);

$('#btn-blur').addEventListener('click', (e) => {
  state.blur = !state.blur;
  e.currentTarget.setAttribute('aria-pressed', String(state.blur));
  e.currentTarget.textContent = state.blur ? 'Reveal values' : 'Blur values';
  renderFindings();
  renderVault();
});

$('#btn-vault-json').addEventListener('click', () => {
  const res = state.result;
  if (!res || !res.vault.length) return toast('No vault to export yet');
  const payload = {
    tool: 'standin',
    version: '0.1.0',
    createdAt: new Date().toISOString(),
    note: 'Keep this file private. It maps placeholders back to the original values.',
    vault: res.vault.map(({ placeholder, id, tag, index, value, ruleId, label, category, severity }) => ({
      placeholder, id, tag, index, value, ruleId, label, category, severity,
    })),
  };
  download(JSON.stringify(payload, null, 2), 'standin-vault.json', 'application/json');
});

document.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
    e.preventDefault();
    runScan();
    toast('Re-scanned');
  }
});

// first paint
setTab('redacted');
render();
