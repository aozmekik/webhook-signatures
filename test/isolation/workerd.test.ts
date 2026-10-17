/**
 * Proof that the library needs nothing from Node.js, part 2: the same
 * scenario runs as a Cloudflare Worker inside workerd (Cloudflare's
 * open-source Workers runtime, driven locally by Miniflare, no network),
 * without the nodejs_compat flag.
 */
import { Miniflare } from 'miniflare';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ScenarioReport } from './scenario.js';
import { EXPECTED_PROVIDERS, bundleForNeutralPlatform } from './bundle.js';

let mf: Miniflare;

beforeAll(async () => {
  const script = await bundleForNeutralPlatform(
    [
      "import { runScenario } from './test/isolation/scenario.ts';",
      'export default { async fetch() { return Response.json(await runScenario()); } };',
    ].join('\n'),
    'esm',
  );
  mf = new Miniflare({ modules: true, script, compatibilityDate: '2026-07-01' });
  await mf.ready;
}, 60_000);

afterAll(async () => {
  await mf.dispose();
});

describe('workerd (Cloudflare Workers runtime)', () => {
  it('signs, verifies and rejects tampering for every provider inside a Worker', async () => {
    const response = await mf.dispatchFetch('http://localhost/');
    expect(response.status).toBe(200);
    const report = (await response.json()) as ScenarioReport;

    expect(report.globals).toEqual({
      process: 'undefined',
      Buffer: 'undefined',
      require: 'undefined',
    });
    expect(Object.keys(report.results)).toEqual(EXPECTED_PROVIDERS);
    for (const id of EXPECTED_PROVIDERS) {
      expect(report.results[id]).toEqual({ provider: id, rejected: 'signature_mismatch' });
    }
  });
});
