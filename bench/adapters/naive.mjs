/**
 * A deliberately naive "regex only, no checksums" detector.
 *
 * It exists to prove the benchmark discriminates: it looks like most
 * hand-rolled redactors (a handful of patterns, no validation) and should
 * score noticeably worse — especially on the hard negatives.
 */
const RULES = [
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, 'email'],
  [/\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g, 'card'],
  [/\b\d{3}-\d{2}-\d{4}\b/g, 'ssn'],
  [/\b\+?\d{1,3}[- ]?\(?\d{2,4}\)?[- ]?\d{3,4}[- ]?\d{3,4}\b/g, 'phone'],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, 'aws-key'],
  [/\bsk-[A-Za-z0-9_-]{16,}\b/g, 'api-key'],
  [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, 'ip'],
  [/\b[A-Z0-9]{20,}\b/g, 'token'],
];

export const name = 'naive-regex';

export default {
  name,
  detect(text) {
    const out = [];
    for (const [re, type] of RULES) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        if (!m[0].length) {
          re.lastIndex += 1;
          continue;
        }
        out.push({ start: m.index, end: m.index + m[0].length, type });
      }
    }
    return out;
  },
};
