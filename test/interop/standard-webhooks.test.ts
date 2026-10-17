/**
 * Cross-validation against the Standard Webhooks reference library, the Svix
 * SDK and the Resend SDK (which verifies Resend's Svix-delivered webhooks).
 * These libraries read the wall clock, so the clock is faked.
 */
import { Resend } from 'resend';
import { Webhook as StandardWebhook } from 'standardwebhooks';
import { Webhook as SvixWebhook } from 'svix';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { verifyStandardWebhook } from 'webhook-signatures';
import { signStandardWebhook } from 'webhook-signatures/testing';
import { NOW, expectCode, shift } from '../support/assertions.js';

const secret = 'whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD';
const id = 'msg_2KWPBgLlAfxdpx2AI54pPJ85f4W';
const payload = JSON.stringify({
  type: 'email.delivered',
  data: { email_id: 'e_1', to: ['ä@example.com'] },
});

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('standardwebhooks interop', () => {
  it('the reference library verifies signStandardWebhook output', async () => {
    const headers = await signStandardWebhook({ payload, secret, id, timestamp: NOW });
    expect(new StandardWebhook(secret).verify(payload, headers)).toEqual(JSON.parse(payload));
  });

  it('verifyStandardWebhook accepts the reference library signature', async () => {
    const signature = new StandardWebhook(secret).sign(id, NOW, payload);
    const headers = {
      'webhook-id': id,
      'webhook-timestamp': String(NOW.getTime() / 1000),
      'webhook-signature': signature,
    };
    expect(signature).toBe(
      (await signStandardWebhook({ payload, secret, id, timestamp: NOW }))['webhook-signature'],
    );
    await expect(verifyStandardWebhook({ payload, headers, secret, now: NOW })).resolves.toEqual({
      provider: 'standard-webhooks',
      id,
      timestamp: NOW,
    });
  });

  it('both reject a message 301 seconds old', async () => {
    const headers = await signStandardWebhook({ payload, secret, id, timestamp: shift(NOW, -301) });
    expect(() => new StandardWebhook(secret).verify(payload, headers)).toThrow(/too old/);
    await expectCode(
      verifyStandardWebhook({ payload, headers, secret }),
      'timestamp_out_of_tolerance',
    );
  });
});

describe('svix interop', () => {
  it('the Svix SDK verifies svix-* headers from signStandardWebhook, including rotation', async () => {
    const headers = await signStandardWebhook({
      payload,
      secret: ['whsec_b2xkLXNlY3JldC1rZXktMTIzNDU2Nzg5MA==', secret],
      id,
      timestamp: NOW,
      headerPrefix: 'svix',
    });
    expect(headers['svix-signature']?.split(' ')).toHaveLength(2);
    // Svix's verify() returns nothing and throws on failure.
    expect(() => {
      new SvixWebhook(secret).verify(payload, headers);
    }).not.toThrow();
  });

  it('verifyStandardWebhook accepts Svix SDK signatures', async () => {
    const signature = new SvixWebhook(secret).sign(id, NOW, payload);
    const headers = {
      'svix-id': id,
      'svix-timestamp': String(NOW.getTime() / 1000),
      'svix-signature': signature,
    };
    await expect(
      verifyStandardWebhook({ payload, headers, secret, now: NOW }),
    ).resolves.toMatchObject({ id });
  });

  it('both reject a tampered body', async () => {
    const headers = await signStandardWebhook({
      payload,
      secret,
      id,
      timestamp: NOW,
      headerPrefix: 'svix',
    });
    const tampered = payload.replace('delivered', 'bounced');
    expect(() => {
      new SvixWebhook(secret).verify(tampered, headers);
    }).toThrow();
    await expectCode(
      verifyStandardWebhook({ payload: tampered, headers, secret }),
      'signature_mismatch',
    );
  });
});

describe('resend interop', () => {
  it("Resend's SDK verifies signStandardWebhook output (Resend delivers through Svix)", async () => {
    const headers = await signStandardWebhook({
      payload,
      secret,
      id,
      timestamp: NOW,
      headerPrefix: 'svix',
    });
    // Constructing the client makes no network request.
    const resend = new Resend('re_placeholder_for_tests');
    const event = resend.webhooks.verify({
      payload,
      webhookSecret: secret,
      headers: {
        id: headers['svix-id'] ?? '',
        timestamp: headers['svix-timestamp'] ?? '',
        signature: headers['svix-signature'] ?? '',
      },
    });
    expect(event).toEqual(JSON.parse(payload));
  });
});
