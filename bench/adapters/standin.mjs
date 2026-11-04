/**
 * standin as a benchmark detector.
 * Enable the experimental name/address rules with STANDIN_EXPERIMENTAL=1.
 */
import { scan, VERSION } from '../../src/standin.js';

export const name = `standin ${VERSION}`;

export default {
  name,
  detect(text) {
    const result = scan(text, { experimental: process.env.STANDIN_EXPERIMENTAL === '1' });
    return result.findings.map((f) => ({
      start: f.start,
      end: f.end,
      type: f.ruleId,
      severity: f.severity,
    }));
  },
};
