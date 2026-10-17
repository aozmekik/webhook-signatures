/**
 * Proof that the library needs nothing from Node.js, part 1.
 *
 * 1. esbuild bundles src/ for `platform: 'neutral'`, where Node built-ins do
 *    not resolve: any `node:*` import would fail the build.
 * 2. The bundle runs inside a fresh @edge-runtime/vm context (the Vercel Edge
 *    Runtime emulation), where `process`, `Buffer` and `require` do not
 *    exist, and every provider signs, verifies and rejects tampering there.
 *
 * Unlike the `edge` Vitest project, nothing here runs in Node's own realm.
 */
import { EdgeVM } from '@edge-runtime/vm';
import { beforeAll, describe, expect, it } from 'vitest';
import type { ScenarioReport } from './scenario.js';
import { EXPECTED_PROVIDERS, bundleForNeutralPlatform } from './bundle.js';

let bundle: string;

beforeAll(async () => {
  bundle = await bundleForNeutralPlatform(
    "import { runScenario } from './test/isolation/scenario.ts';\nglobalThis.runScenario = runScenario;",
    'iife',
  );
});

describe('edge-runtime VM isolation', () => {
  it('bundles for a neutral platform without Node built-ins', () => {
    expect(bundle.length).toBeGreaterThan(0);
    expect(bundle).not.toMatch(/\brequire\(|from ["']node:/);
  });

  it('signs, verifies and rejects tampering for every provider inside the VM', async () => {
    const vm = new EdgeVM();
    expect(vm.evaluate<string>('typeof EdgeRuntime')).toBe('string');
    vm.evaluate(bundle);
    const json = await vm.evaluate<Promise<string>>('runScenario().then(JSON.stringify)');
    const report = JSON.parse(json) as ScenarioReport;

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
