import { afterEach, describe, expect, it, vi } from 'vitest';
import { verifyGitHub } from 'webhook-signatures';
import { signGitHub } from 'webhook-signatures/testing';

describe('runtime requirements', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // That nothing beyond Web-standard globals is needed is proven by
  // test/isolation, which runs the bundled library without Node's globals.
  it('round-trips with the default globals', async () => {
    const payload = 'ok';
    const headers = await signGitHub({ payload, secret: 's' });
    await expect(verifyGitHub({ payload, headers, secret: 's' })).resolves.toBeDefined();
  });

  it('fails with a clear message when Web Crypto is unavailable', async () => {
    vi.stubGlobal('crypto', undefined);
    await expect(
      verifyGitHub({
        payload: 'x',
        headers: { 'x-hub-signature-256': `sha256=${'0'.repeat(64)}` },
        secret: 's',
      }),
    ).rejects.toThrow(/requires the Web Crypto API/);
    vi.stubGlobal('crypto', {});
    await expect(signGitHub({ payload: 'x', secret: 's' })).rejects.toThrow(
      /requires the Web Crypto API/,
    );
  });
});
