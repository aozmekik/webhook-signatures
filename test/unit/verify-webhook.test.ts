import { describe, expect, expectTypeOf, it } from 'vitest';
import { verifyWebhook } from 'webhook-signatures';
import type {
  GitHubVerifyResult,
  HeadersInput,
  ProviderId,
  StripeVerifyResult,
  VerifyWebhookOptions,
} from 'webhook-signatures';
import { signStandardWebhook, signStripe } from 'webhook-signatures/testing';
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

  it('requires options that suit every provider when the provider is a union', async () => {
    interface Base {
      payload: string;
      headers: HeadersInput;
      secret: string;
    }
    expectTypeOf<Base>().not.toExtend<VerifyWebhookOptions<'twilio' | 'github'>>();
    expectTypeOf<Base>().not.toExtend<VerifyWebhookOptions<ProviderId>>();
    expectTypeOf<Base>().toExtend<VerifyWebhookOptions<'stripe' | 'github' | 'shopify'>>();
    expectTypeOf(verifyWebhook<'stripe' | 'github'>).returns.resolves.toEqualTypeOf<
      StripeVerifyResult | GitHubVerifyResult
    >();

    // A provider known only as a union, as from a route parameter.
    const provider = 'github' as 'twilio' | 'github';
    const options = { payload: '{}', headers: {}, secret: 's' };
    // @ts-expect-error url is required while the provider may be 'twilio'
    await expectCode(verifyWebhook(provider, options), 'missing_header');
    await expectCode(verifyWebhook(provider, { ...options, url: TWILIO_URL }), 'missing_header');
  });
});

describe('sign* header types', () => {
  it('name the headers they return, so reads need no undefined check', async () => {
    const stripe = await signStripe({ payload: '{}', secret: 'whsec_x' });
    expectTypeOf(stripe['stripe-signature']).toEqualTypeOf<string>();
    const svix = await signStandardWebhook({
      payload: '{}',
      secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
      id: 'msg_1',
      headerPrefix: 'svix',
    });
    expectTypeOf(svix).toEqualTypeOf<
      Record<'svix-id' | 'svix-timestamp' | 'svix-signature', string>
    >();
    expect(Object.keys(svix)).toEqual(['svix-id', 'svix-timestamp', 'svix-signature']);
    const standard = await signStandardWebhook({
      payload: '{}',
      secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
      id: 'msg_1',
    });
    expectTypeOf(standard).toEqualTypeOf<
      Record<'webhook-id' | 'webhook-timestamp' | 'webhook-signature', string>
    >();
  });
});
