/**
 * Cross-validation against the official Stripe SDK (stripe-node): headers
 * produced by either side must verify with the other.
 */
import Stripe from 'stripe';
import { describe, expect, it } from 'vitest';
import { verifyStripe } from 'webhook-signatures';
import { signStripe } from 'webhook-signatures/testing';
import { NOW, expectCode, shift } from '../support/assertions.js';

const secret = 'whsec_test_interop_secret';
const payload = JSON.stringify({
  id: 'evt_1Interop',
  object: 'event',
  type: 'payment_intent.succeeded',
  data: { object: { id: 'pi_1', amount: 4200, description: 'çay ☕' } },
});
const nowSeconds = NOW.getTime() / 1000;

describe('stripe-node interop', () => {
  it('stripe-node accepts headers from signStripe (sync and Web Crypto providers)', async () => {
    const header =
      (await signStripe({ payload, secret, timestamp: NOW }))['stripe-signature'] ?? '';
    const event = Stripe.webhooks.constructEvent(
      payload,
      header,
      secret,
      300,
      undefined,
      NOW.getTime(),
    );
    expect(event.id).toBe('evt_1Interop');
    const viaSubtle = await Stripe.webhooks.constructEventAsync(
      payload,
      header,
      secret,
      300,
      Stripe.createSubtleCryptoProvider(),
      NOW.getTime(),
    );
    expect(viaSubtle.id).toBe('evt_1Interop');
  });

  it('stripe-node accepts a rotation header from signStripe with either secret', async () => {
    const header =
      (await signStripe({ payload, secret: [secret, 'whsec_old'], timestamp: NOW }))[
        'stripe-signature'
      ] ?? '';
    for (const key of [secret, 'whsec_old']) {
      expect(
        Stripe.webhooks.constructEvent(payload, header, key, 300, undefined, NOW.getTime()).id,
      ).toBe('evt_1Interop');
    }
  });

  it('verifyStripe accepts headers from generateTestHeaderString', async () => {
    const header = Stripe.webhooks.generateTestHeaderString({
      payload,
      secret,
      timestamp: nowSeconds,
    });
    await expect(
      verifyStripe({ payload, headers: { 'Stripe-Signature': header }, secret, now: NOW }),
    ).resolves.toEqual({ provider: 'stripe', timestamp: NOW });
  });

  it('agrees with stripe-node byte for byte', async () => {
    const ours = await signStripe({ payload, secret, timestamp: NOW });
    const theirs = Stripe.webhooks.generateTestHeaderString({
      payload,
      secret,
      timestamp: nowSeconds,
    });
    expect(ours['stripe-signature']).toBe(theirs);
  });

  it('both reject a tampered payload and an expired timestamp', async () => {
    const header = Stripe.webhooks.generateTestHeaderString({
      payload,
      secret,
      timestamp: nowSeconds,
    });
    const tampered = payload.replace('4200', '4201');
    expect(() =>
      Stripe.webhooks.constructEvent(tampered, header, secret, 300, undefined, NOW.getTime()),
    ).toThrow(Stripe.errors.StripeSignatureVerificationError);
    await expectCode(
      verifyStripe({
        payload: tampered,
        headers: { 'stripe-signature': header },
        secret,
        now: NOW,
      }),
      'signature_mismatch',
    );

    const late = shift(NOW, 301).getTime();
    expect(() =>
      Stripe.webhooks.constructEvent(payload, header, secret, 300, undefined, late),
    ).toThrow(/tolerance/);
    await expectCode(
      verifyStripe({
        payload,
        headers: { 'stripe-signature': header },
        secret,
        now: new Date(late),
      }),
      'timestamp_out_of_tolerance',
    );
  });
});
