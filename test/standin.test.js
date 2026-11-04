import test from 'node:test';
import assert from 'node:assert/strict';
import { scan, redact, restore, entropy } from '../src/standin.js';

const scrub = (text, opts) => redact(text, opts).text;

test('redacts email addresses, keeping one placeholder per value', () => {
  const { text, vault } = redact('from a.mensah@example.co.ug to a.mensah@example.co.ug');
  assert.equal(text, 'from [EMAIL_1] to [EMAIL_1]');
  assert.equal(vault.length, 1);
  assert.equal(vault[0].value, 'a.mensah@example.co.ug');
});

test('redacts phone numbers in common shapes', () => {
  assert.match(scrub('call +256 772 123 456 now'), /\[PHONE_1\]/);
  assert.match(scrub('call (415) 555-0132 now'), /\[PHONE_1\]/);
  assert.match(scrub('call 0772-123-456 now'), /\[PHONE_1\]/);
});

test('leaves dates and years alone', () => {
  assert.equal(scrub('between 2024-01-15 and 2025-06-01'), 'between 2024-01-15 and 2025-06-01');
  assert.equal(scrub('founded in 2016'), 'founded in 2016');
});

test('card numbers need a valid Luhn checksum', () => {
  assert.match(scrub('card 4111 1111 1111 1111 please'), /\[CARD_1\]/);
  assert.equal(scrub('order 4111 1111 1111 1112 please'), 'order 4111 1111 1111 1112 please');
});

test('IBAN needs a valid mod-97 checksum', () => {
  assert.match(scrub('pay to GB82 WEST 1234 5698 7654 32'), /\[IBAN_1\]/);
  assert.equal(scrub('pay to GB82 WEST 1234 5698 7654 33'), 'pay to GB82 WEST 1234 5698 7654 33');
});

test('catches the usual API key shapes', () => {
  assert.match(scrub('key AKIAIOSFODNN7EXAMPLE'), /\[AWS_KEY_1\]/);
  assert.match(scrub('token ghp_abcdefghijklmnopqrstuvwxyz0123456789'), /\[GH_TOKEN_1\]/);
  assert.match(scrub('token sk-abcdefghijklmnopqrstuvwxyz123456'), /\[API_KEY_1\]/);
  assert.match(scrub('auth Bearer abcdefghijklmnop1234567890'), /\[TOKEN_1\]/);
  assert.match(scrub('postgres://admin:hunter2@db.internal:5432/app'), /\[CRED_URL_1\]/);
});

test('catches passwords in key/value pairs but not placeholders', () => {
  const out = scrub('password: hunter2hunter2');
  assert.match(out, /\[SECRET_1\]/);
  assert.equal(scrub('password: ${DB_PASSWORD}'), 'password: ${DB_PASSWORD}');
  assert.equal(scrub('api_key = [REDACTED]'), 'api_key = [REDACTED]');
  assert.equal(scrub('password: null'), 'password: null');
});

test('catches high-entropy blobs and JWT', () => {
  const blob = 'Zx8Kq2LmP0vN4bT7yR1cW6sD9fG3hJ5k';
  assert.match(scrub(`secret ${blob}`), /\[(?:SECRET|SECRET_1|SECRET_2)_?\d*\]/);
  const jwt =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
  assert.match(scrub(`token ${jwt}`), /\[JWT_1\]/);
});

test('redacts IPs and MACs, keeps loopback', () => {
  assert.match(scrub('host 10.20.30.40'), /\[IP_1\]/);
  assert.equal(scrub('host 127.0.0.1'), 'host 127.0.0.1');
  assert.match(scrub('mac 00:1A:2B:3C:4D:5E'), /\[MAC_1\]/);
});

test('private key blocks are replaced whole', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\nabcd\n-----END RSA PRIVATE KEY-----';
  const out = scrub(`here:\n${pem}\ndone`);
  assert.equal(out, 'here:\n[PRIVATE_KEY_1]\ndone');
});

test('names and addresses are opt-in', () => {
  const text = 'Regards, Amina Nakato\n12 Kimathi Street, Nairobi 00100';
  assert.equal(scrub(text), text);
  const out = scrub(text, { experimental: true });
  assert.match(out, /\[NAME_1\]/);
  assert.match(out, /\[ADDRESS_1\]/);
});

test('category filter limits what is caught', () => {
  const text = 'mail a@b.co from 10.0.0.9';
  const out = scrub(text, { categories: ['network'] });
  assert.equal(out, 'mail a@b.co from [IP_1]');
});

test('brace mask style', () => {
  assert.equal(scrub('a@b.co', { mask: 'brace' }), '{{EMAIL_1}}');
});

test('scan is idempotent', () => {
  const once = scrub('mail a@b.co, ip 10.0.0.9, key AKIAIOSFODNN7EXAMPLE');
  assert.equal(scrub(once), once);
});

test('round-trip: restore puts the originals back', () => {
  const source = 'Mail a.mensah@example.co.ug or call +256 772 123 456. Card 4111 1111 1111 1111.';
  const { text, vault } = redact(source);
  const answer = `Sure — I emailed ${'[EMAIL_1]'} and called ${'[PHONE_1]'}. The card ${'[CARD_1]'} is fine.`;
  const restored = restore(answer, vault);
  assert.match(restored, /a\.mensah@example\.co\.ug/);
  assert.match(restored, /\+256 772 123 456/);
  assert.match(restored, /4111 1111 1111 1111/);
  assert.equal(restore(source, vault), source);
});

test('restore tolerates models that dropped the brackets', () => {
  const { vault } = redact('a@b.co');
  assert.equal(restore('emailed EMAIL_1 today', vault), 'emailed a@b.co today');
});

test('vault seeding keeps placeholders stable across chunks', () => {
  const first = redact('a@b.co');
  const second = redact('c@d.co and a@b.co', { vault: first.vault });
  assert.match(second.text, /\[EMAIL_1\]/);
  assert.match(second.text, /\[EMAIL_2\]/);
  assert.equal(second.vault.length, 2);
});

test('entropy sanity', () => {
  assert.ok(entropy('aaaaaaaa') < 0.1);
  assert.ok(entropy('aB3$xY7!qZ2') > 3);
});

test('does not touch ordinary prose or version numbers', () => {
  const text = 'Version 1.2.3 shipped on Monday with 12 new tests and 3 fixes.';
  assert.equal(scrub(text), text);
  const prose = 'The quick brown fox jumps over the lazy dog, repeatedly and with great enthusiasm.';
  assert.equal(scrub(prose), prose);
});
