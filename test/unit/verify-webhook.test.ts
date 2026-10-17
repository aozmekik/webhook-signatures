import { describe, expect, expectTypeOf, it } from 'vitest';
import { verifyWebhook } from 'webhook-signatures';
import type { GitHubVerifyResult, ProviderId, StripeVerifyResult } from 'webhook-signatures';
import { NOW, expectCode } from '../support/assertions.js';
import { TWILIO_URL, providerCases } from '../support/providers.js';

describe('verifyWebhook', () => {
  it.each(providerCases)('dispatches to the $id verifier', async (provider) => {
    const { secret, samplePayload: payload } = provider;
    const headers = await provider.sign({ payload, secret, timestamp: NOW });
    const options = { payload, headers, secret, now: NOW, url: TWILIO_URL };
    await expect(verifyWebhook(provider.id, options)).resolves.toMatchObject({
      provider: provider.id,
    });
    await expectCode(
      verifyWebhook(provider.id, { ...options, secret: provider.otherSecret }),
      'signature_mismatch',
    );
  });

  it('rejects unknown providers with a TypeError', async () => {
    for (const id of ['paypal', 'toString', '__proto__', 1]) {
      await expect(
        verifyWebhook(id as ProviderId, { payload: '', headers: {}, secret: 's', url: '' }),
      ).rejects.toThrow(TypeError);
    }
  });

  it('types options and results per provider', () => {
    expectTypeOf(verifyWebhook<'stripe'>).returns.resolves.toEqualTypeOf<StripeVerifyResult>();
    expectTypeOf(verifyWebhook<'github'>).returns.resolves.toEqualTypeOf<GitHubVerifyResult>();
    expectTypeOf(verifyWebhook<'twilio'>)
      .parameter(1)
      .toHaveProperty('url');
  });
});
