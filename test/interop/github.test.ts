/** Cross-validation against GitHub's @octokit/webhooks-methods. */
import { sign, verify } from '@octokit/webhooks-methods';
import { describe, expect, it } from 'vitest';
import { verifyGitHub } from 'webhook-signatures';
import { signGitHub } from 'webhook-signatures/testing';
import { expectCode } from '../support/assertions.js';

const secret = 'octokit-interop-secret';
const payloads = [
  JSON.stringify({ action: 'opened', issue: { title: 'Ünïcödé 🎉' } }),
  'Hello, World!',
];

describe('@octokit/webhooks-methods interop', () => {
  it.each(payloads)('octokit verifies signGitHub output (%#)', async (payload) => {
    const header = (await signGitHub({ payload, secret }))['x-hub-signature-256'] ?? '';
    expect(await verify(secret, payload, header)).toBe(true);
  });

  it.each(payloads)('verifyGitHub accepts octokit sign output (%#)', async (payload) => {
    const header = await sign(secret, payload);
    expect(header).toBe((await signGitHub({ payload, secret }))['x-hub-signature-256']);
    await expect(
      verifyGitHub({ payload, headers: { 'X-Hub-Signature-256': header }, secret }),
    ).resolves.toMatchObject({ provider: 'github' });
  });

  it('both reject a different secret', async () => {
    const payload = payloads[0] ?? '';
    const header = await sign(secret, payload);
    expect(await verify('other', payload, header)).toBe(false);
    await expectCode(
      verifyGitHub({ payload, headers: { 'x-hub-signature-256': header }, secret: 'other' }),
      'signature_mismatch',
    );
  });
});
