/**
 * Proof that the library needs nothing from Node.js.
 *
 * 1. esbuild bundles src/ for `platform: 'neutral'`, where Node built-ins do
 *    not resolve: any `node:*` import would fail the build.
 * 2. The bundle is evaluated inside a fresh @edge-runtime/vm context (the
 *    Vercel Edge Runtime emulation), where `process`, `Buffer` and `require`
 *    do not exist, and every provider signs, verifies and rejects tampering
 *    there.
 *
 * Unlike the `edge` Vitest project, nothing here runs in Node's own realm.
 */
import { fileURLToPath } from 'node:url';
import { EdgeVM } from '@edge-runtime/vm';
import { build } from 'esbuild';
import { beforeAll, describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('../..', import.meta.url));

let bundle: string;

beforeAll(async () => {
  const result = await build({
    stdin: {
      contents: "export * from './src/index.ts';\nexport * from './src/testing.ts';",
      resolveDir: root,
      loader: 'ts',
    },
    bundle: true,
    write: false,
    platform: 'neutral',
    format: 'iife',
    globalName: 'WebhookSignatures',
    target: 'es2022',
    logLevel: 'silent',
  });
  bundle = result.outputFiles[0]?.text ?? '';
});

const scenario = `(async () => {
  const W = WebhookSignatures;
  const now = new Date('2026-03-14T15:09:26Z');
  const payload = new TextEncoder().encode(JSON.stringify({ hello: 'edge', note: 'çağ' }));
  const tampered = new TextEncoder().encode(JSON.stringify({ hello: 'edgf', note: 'çağ' }));
  const url = 'https://example.com/hook';
  const cases = [
    ['stripe', W.signStripe, W.verifyStripe, 'whsec_edge'],
    ['github', W.signGitHub, W.verifyGitHub, 'gh'],
    ['slack', W.signSlack, W.verifySlack, 'slack'],
    ['shopify', W.signShopify, W.verifyShopify, 'shopify'],
    ['standard-webhooks', (o) => W.signStandardWebhook({ ...o, id: 'msg_1' }), W.verifyStandardWebhook, 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'],
    ['twilio', async (o) => (await W.signTwilio({ ...o, url, scheme: 'body-sha256' })).headers, (o) => W.verifyTwilio({ ...o, url: url + '?bodySHA256=' + o.bodyHash }), 'token'],
    ['paddle', W.signPaddle, W.verifyPaddle, 'pdl_ntfset_edge'],
    ['lemon-squeezy', W.signLemonSqueezy, W.verifyLemonSqueezy, 'lemon'],
  ];
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', payload));
  const bodyHash = Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
  const results = {};
  for (const [id, sign, verify, secret] of cases) {
    const headers = await sign({ payload, secret, timestamp: now });
    const verified = await verify({ payload, headers: new Headers(headers), secret, now, bodyHash });
    let rejected = 'accepted';
    try {
      await verify({ payload: tampered, headers, secret, now, bodyHash });
    } catch (error) {
      rejected = error instanceof W.WebhookVerificationError ? error.code : String(error);
    }
    results[id] = { provider: verified.provider, rejected };
  }
  return JSON.stringify({
    globals: { process: typeof process, Buffer: typeof Buffer, require: typeof require, EdgeRuntime: typeof EdgeRuntime },
    results,
  });
})()`;

describe('edge-runtime VM isolation', () => {
  it('bundles for a neutral platform without Node built-ins', () => {
    expect(bundle.length).toBeGreaterThan(0);
    expect(bundle).not.toMatch(/\brequire\(|from ["']node:/);
  });

  it('signs, verifies and rejects tampering for every provider inside the VM', async () => {
    const vm = new EdgeVM();
    vm.evaluate(bundle);
    const json = await vm.evaluate<Promise<string>>(scenario);
    const output = JSON.parse(json) as {
      globals: Record<string, string>;
      results: Record<string, { provider: string; rejected: string }>;
    };

    expect(output.globals).toEqual({
      process: 'undefined',
      Buffer: 'undefined',
      require: 'undefined',
      EdgeRuntime: 'string',
    });
    const providers = [
      'stripe',
      'github',
      'slack',
      'shopify',
      'standard-webhooks',
      'twilio',
      'paddle',
      'lemon-squeezy',
    ];
    expect(Object.keys(output.results)).toEqual(providers);
    for (const id of providers) {
      expect(output.results[id]).toEqual({ provider: id, rejected: 'signature_mismatch' });
    }
  });
});
