/** Provider-specific behaviour that the shared conformance suite does not cover. */
import { describe, expect, it } from 'vitest';
import {
  WebhookVerificationError,
  verifyGitHub,
  verifyLemonSqueezy,
  verifyPaddle,
  verifyShopify,
  verifySlack,
  verifyStandardWebhook,
  verifyStripe,
  verifyTwilio,
} from 'webhook-signatures';
import {
  signGitHub,
  signLemonSqueezy,
  signPaddle,
  signShopify,
  signSlack,
  signStandardWebhook,
  signStripe,
  signTwilio,
} from 'webhook-signatures/testing';
import { NOW, expectCode, shift, withHeader } from '../support/assertions.js';

const payload = JSON.stringify({ hello: 'world' });

describe('Stripe', () => {
  const secret = 'whsec_test_secret';

  it('ignores v0 test signatures and unknown schemes next to a valid v1', async () => {
    const signed = await signStripe({ payload, secret, timestamp: NOW });
    const value = `${signed['stripe-signature'] ?? ''},v0=${'00'.repeat(32)},v9=future`;
    await expect(
      verifyStripe({ payload, headers: { 'stripe-signature': value }, secret, now: NOW }),
    ).resolves.toEqual({ provider: 'stripe', timestamp: NOW });
  });

  it('tolerates whitespace around elements and upper-case hex', async () => {
    const signed =
      (await signStripe({ payload, secret, timestamp: NOW }))['stripe-signature'] ?? '';
    const [ts, v1] = signed.split(',');
    const value = ` ${ts ?? ''} , ${(v1 ?? '').toUpperCase().replace('V1=', 'v1=')} `;
    await expect(
      verifyStripe({ payload, headers: { 'stripe-signature': value }, secret, now: NOW }),
    ).resolves.toBeDefined();
  });

  it('signs over the timestamp text exactly as sent', async () => {
    // A leading zero changes the signed string, so it must not be normalised away.
    const signed =
      (await signStripe({ payload, secret, timestamp: NOW }))['stripe-signature'] ?? '';
    const zeroPadded = signed.replace('t=', 't=0');
    await expectCode(
      verifyStripe({ payload, headers: { 'stripe-signature': zeroPadded }, secret, now: NOW }),
      'signature_mismatch',
    );
  });

  it('formats the header like Stripe: t first, then one v1 per secret', async () => {
    const headers = await signStripe({ payload, secret: ['a', 'b'], timestamp: NOW });
    expect(headers['stripe-signature']).toMatch(/^t=\d+,v1=[0-9a-f]{64},v1=[0-9a-f]{64}$/);
  });

  it('rejects signing timestamps that cannot be represented', async () => {
    await expect(signStripe({ payload, secret, timestamp: new Date(Number.NaN) })).rejects.toThrow(
      TypeError,
    );
    await expect(signStripe({ payload, secret, timestamp: new Date(-1000) })).rejects.toThrow(
      RangeError,
    );
  });
});

describe('GitHub', () => {
  const secret = 'gh-secret';

  it('returns the unsigned delivery metadata headers', async () => {
    const headers = {
      ...(await signGitHub({ payload, secret })),
      'X-GitHub-Delivery': '72d3162e-cc78-11e3-81ab-4c9367dc0958',
      'X-GitHub-Event': 'issues',
    };
    await expect(verifyGitHub({ payload, headers, secret })).resolves.toEqual({
      provider: 'github',
      deliveryId: '72d3162e-cc78-11e3-81ab-4c9367dc0958',
      event: 'issues',
    });
  });

  it('explains when only the legacy SHA-1 header was sent', async () => {
    const error = await expectCode(
      verifyGitHub({ payload, secret, headers: { 'X-Hub-Signature': `sha1=${'0'.repeat(40)}` } }),
      'missing_header',
    );
    expect(error.message).toContain('legacy');
  });

  it('signs with the first secret of a list', async () => {
    expect(await signGitHub({ payload, secret: ['first', 'second'] })).toEqual(
      await signGitHub({ payload, secret: 'first' }),
    );
  });
});

describe('Slack', () => {
  const secret = 'slack-signing-secret';

  it('requires both headers', async () => {
    const signed = await signSlack({ payload, secret, timestamp: NOW });
    for (const name of ['x-slack-signature', 'x-slack-request-timestamp']) {
      const error = await expectCode(
        verifySlack({ payload, headers: withHeader(signed, name, undefined), secret, now: NOW }),
        'missing_header',
      );
      expect(error.header).toBe(name);
    }
  });

  it('binds the timestamp into the signature', async () => {
    const signed = await signSlack({ payload, secret, timestamp: NOW });
    const later = String(NOW.getTime() / 1000 + 1);
    await expectCode(
      verifySlack({
        payload,
        headers: withHeader(signed, 'x-slack-request-timestamp', later),
        secret,
        now: NOW,
      }),
      'signature_mismatch',
    );
  });
});

describe('Shopify', () => {
  it('returns the unsigned webhook id and topic headers', async () => {
    const secret = 'shopify-secret';
    const headers = new Headers(await signShopify({ payload, secret }));
    headers.set('X-Shopify-Webhook-Id', 'b54557e4-bdd9-4b37-8a5f-bf7d70bcd043');
    headers.set('X-Shopify-Topic', 'orders/create');
    await expect(verifyShopify({ payload, headers, secret })).resolves.toEqual({
      provider: 'shopify',
      webhookId: 'b54557e4-bdd9-4b37-8a5f-bf7d70bcd043',
      topic: 'orders/create',
    });
  });
});

describe('Standard Webhooks', () => {
  const secret = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
  const id = 'msg_p5jXN8AQM9LWM0D4loKWxJek';

  it('accepts the secret with or without the whsec_ prefix', async () => {
    const headers = await signStandardWebhook({ payload, secret, id, timestamp: NOW });
    const bare = secret.slice('whsec_'.length);
    await expect(
      verifyStandardWebhook({ payload, headers, secret: bare, now: NOW }),
    ).resolves.toEqual({ provider: 'standard-webhooks', id, timestamp: NOW });
  });

  it('rejects secrets that are not base64', async () => {
    const headers = await signStandardWebhook({ payload, secret, id, timestamp: NOW });
    for (const bad of ['whsec_', 'whsec_not base64!', 'whsec_abcde']) {
      await expectCode(
        verifyStandardWebhook({ payload, headers, secret: bad, now: NOW }),
        'invalid_secret',
      );
    }
  });

  it('reads svix-* headers when webhook-* headers are absent', async () => {
    const headers = await signStandardWebhook({
      payload,
      secret,
      id,
      timestamp: NOW,
      headerPrefix: 'svix',
    });
    expect(Object.keys(headers)).toEqual(['svix-id', 'svix-timestamp', 'svix-signature']);
    await expect(
      verifyStandardWebhook({ payload, headers, secret, now: NOW }),
    ).resolves.toBeDefined();
  });

  it('prefers webhook-* headers when both sets are present', async () => {
    const good = await signStandardWebhook({ payload, secret, id, timestamp: NOW });
    const stale = await signStandardWebhook({
      payload: 'other',
      secret,
      id: 'msg_other',
      timestamp: NOW,
      headerPrefix: 'svix',
    });
    await expect(
      verifyStandardWebhook({ payload, headers: { ...stale, ...good }, secret, now: NOW }),
    ).resolves.toMatchObject({ id });
  });

  it('binds the message id into the signature', async () => {
    const headers = await signStandardWebhook({ payload, secret, id, timestamp: NOW });
    await expectCode(
      verifyStandardWebhook({
        payload,
        headers: withHeader(headers, 'webhook-id', 'msg_replayed'),
        secret,
        now: NOW,
      }),
      'signature_mismatch',
    );
  });

  it('requires all three headers', async () => {
    const signed = await signStandardWebhook({ payload, secret, id, timestamp: NOW });
    for (const name of ['webhook-id', 'webhook-timestamp']) {
      const error = await expectCode(
        verifyStandardWebhook({
          payload,
          headers: withHeader(signed, name, undefined),
          secret,
          now: NOW,
        }),
        'missing_header',
      );
      expect(error.header).toBe(name);
    }
  });

  it('validates the id when signing', async () => {
    await expect(signStandardWebhook({ payload, secret, id: '' })).rejects.toThrow(TypeError);
  });
});

describe('Twilio', () => {
  const secret = 'twilio-auth-token';
  const form = 'Body=Hello+there&From=%2B15005550006&To=%2B15005550001&MessageSid=SM123';

  it('verifies when the configured URL and the reconstructed URL differ only by the default port', async () => {
    const signedWithPort = await signTwilio({
      payload: form,
      secret,
      url: 'https://example.com:443/sms',
    });
    await expect(
      verifyTwilio({
        payload: form,
        headers: signedWithPort.headers,
        secret,
        url: 'https://example.com/sms',
      }),
    ).resolves.toEqual({ provider: 'twilio', scheme: 'form-params' });

    const signedWithoutPort = await signTwilio({
      payload: form,
      secret,
      url: 'https://example.com/sms',
    });
    await expect(
      verifyTwilio({
        payload: form,
        headers: signedWithoutPort.headers,
        secret,
        url: 'https://example.com:443/sms',
      }),
    ).resolves.toBeDefined();
  });

  it('verifies when Twilio dropped a non-default port (voice over HTTPS)', async () => {
    const signed = await signTwilio({ payload: form, secret, url: 'https://example.com/voice' });
    await expect(
      verifyTwilio({
        payload: form,
        headers: signed.headers,
        secret,
        url: 'https://example.com:8443/voice',
      }),
    ).resolves.toBeDefined();
  });

  it('handles IPv6 hosts and plain HTTP', async () => {
    const signed = await signTwilio({ payload: form, secret, url: 'http://[2001:db8::1]:80/hook' });
    await expect(
      verifyTwilio({
        payload: form,
        headers: signed.headers,
        secret,
        url: 'http://[2001:db8::1]/hook',
      }),
    ).resolves.toBeDefined();
  });

  it('drops URL credentials before verifying, as Twilio does when signing', async () => {
    const signed = await signTwilio({ payload: form, secret, url: 'https://example.com/sms' });
    await expect(
      verifyTwilio({
        payload: form,
        headers: signed.headers,
        secret,
        url: 'https://user:pa%40ss@example.com/sms',
      }),
    ).resolves.toBeDefined();
  });

  it('signs the query string, so changing it fails', async () => {
    const url = 'https://example.com/sms?tenant=a';
    const signed = await signTwilio({ payload: form, secret, url });
    await expectCode(
      verifyTwilio({ payload: form, headers: signed.headers, secret, url: `${url}b` }),
      'signature_mismatch',
    );
  });

  it('ignores parameter order but not parameter values', async () => {
    const url = 'https://example.com/sms';
    const signed = await signTwilio({ payload: form, secret, url });
    const reordered = form.split('&').reverse().join('&');
    await expect(
      verifyTwilio({ payload: reordered, headers: signed.headers, secret, url }),
    ).resolves.toBeDefined();
    await expectCode(
      verifyTwilio({
        payload: form.replace('Hello', 'Hullo'),
        headers: signed.headers,
        secret,
        url,
      }),
      'signature_mismatch',
    );
  });

  it('sorts repeated parameter values', async () => {
    const url = 'https://example.com/status';
    const signed = await signTwilio({ payload: 'Tag=b&Tag=a&Tag=b', secret, url });
    await expect(
      verifyTwilio({ payload: 'Tag=a&Tag=b', headers: signed.headers, secret, url }),
    ).resolves.toBeDefined();
  });

  it('verifies GET requests with an empty body', async () => {
    const url = 'https://example.com/voice?CallSid=CA1&From=%2B1500';
    const signed = await signTwilio({ payload: '', secret, url });
    await expect(
      verifyTwilio({ payload: '', headers: signed.headers, secret, url }),
    ).resolves.toEqual({
      provider: 'twilio',
      scheme: 'form-params',
    });
  });

  describe('JSON bodies (bodySHA256)', () => {
    const body = JSON.stringify({ CallSid: 'CA123', Caller: '+12349013030' });
    const json = { scheme: 'body-sha256' } as const;

    it('verifies the URL signature and the body hash', async () => {
      const signed = await signTwilio({
        payload: body,
        secret,
        url: 'https://example.com/json?x=1',
        ...json,
      });
      expect(signed.url).toMatch(/^https:\/\/example\.com\/json\?x=1&bodySHA256=[0-9a-f]{64}$/);
      await expect(
        verifyTwilio({ payload: body, headers: signed.headers, secret, url: signed.url, ...json }),
      ).resolves.toEqual({ provider: 'twilio', scheme: 'body-sha256' });
    });

    it('is not inferred from the URL: the default scheme is form-params', async () => {
      const signed = await signTwilio({
        payload: body,
        secret,
        url: 'https://example.com/json',
        ...json,
      });
      const error = await expectCode(
        verifyTwilio({ payload: body, headers: signed.headers, secret, url: signed.url }),
        'signature_mismatch',
      );
      expect(error.message).toContain('pass scheme "body-sha256"');
    });

    it('accepts an upper-case body hash in the URL', async () => {
      const signed = await signTwilio({
        payload: body,
        secret,
        url: 'https://example.com/json',
        ...json,
      });
      const upperUrl = signed.url.replace(
        /=([0-9a-f]+)$/,
        (_m, h: string) => `=${h.toUpperCase()}`,
      );
      const resigned = await signTwilio({ payload: '', secret, url: upperUrl });
      await expect(
        verifyTwilio({ payload: body, headers: resigned.headers, secret, url: upperUrl, ...json }),
      ).resolves.toBeDefined();
    });

    it('rejects a body that does not match the signed hash', async () => {
      const signed = await signTwilio({
        payload: body,
        secret,
        url: 'https://example.com/json',
        ...json,
      });
      const error = await expectCode(
        verifyTwilio({
          payload: `${body} `,
          headers: signed.headers,
          secret,
          url: signed.url,
          ...json,
        }),
        'signature_mismatch',
      );
      expect(error.message).toContain('bodySHA256');
    });

    it('rejects a hash added to a URL that was signed without one', async () => {
      const signed = await signTwilio({ payload: body, secret, url: 'https://example.com/json' });
      const forged = await signTwilio({
        payload: body,
        secret: 'attacker',
        url: 'https://example.com/json',
        ...json,
      });
      await expectCode(
        verifyTwilio({ payload: body, headers: signed.headers, secret, url: forged.url, ...json }),
        'signature_mismatch',
      );
    });

    it('requires the URL to end with exactly one bodySHA256 and no fragment', async () => {
      const hash = 'ab'.repeat(32);
      for (const url of [
        'https://example.com/json',
        'https://example.com/json?x=1',
        `https://example.com/json?bodySHA256=${hash}&x=1`,
        `https://example.com/json?bodySHA256=${hash}&bodySHA256=${hash}`,
        `https://example.com/json?bodySHA256=${hash}#f`,
      ]) {
        // Signed with the right token, so only the URL shape can fail.
        const { headers } = await signTwilio({ payload: '', secret, url });
        const error = await expectCode(
          verifyTwilio({ payload: body, headers, secret, url, ...json }),
          'signature_mismatch',
        );
        expect(error.message).toContain('must end with the single bodySHA256');
      }
    });

    it('rejects a form-params signature re-assembled into a JSON request (scheme confusion)', async () => {
      // Regression test for a reported forgery. An attacker gets Twilio to
      // sign a form webhook whose Body (an SMS text) plants a bodySHA256 for
      // a JSON body of their choosing, captures the signature, and re-reads
      // the signed string "URL + name + value + ..." as one longer URL.
      const configured = 'https://example.com/sms?tenant=acme';
      const attackerBody = JSON.stringify({ Body: 'forged', From: '+15550000000' });
      const hash = [
        ...new Uint8Array(
          await crypto.subtle.digest('SHA-256', new TextEncoder().encode(attackerBody)),
        ),
      ]
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      const captured = await signTwilio({
        payload: new URLSearchParams({
          AccountSid: 'AC123',
          Body: `&bodySHA256=${hash}&x=`,
          From: '+15551234567',
        }).toString(),
        secret,
        url: configured,
      });
      const forgedUrl = `${configured}AccountSidAC123Body&bodySHA256=${hash}&x=From+15551234567`;
      const forged = { payload: attackerBody, headers: captured.headers, secret, url: forgedUrl };
      await expectCode(verifyTwilio(forged), 'signature_mismatch');
      await expectCode(verifyTwilio({ ...forged, scheme: 'form-params' }), 'signature_mismatch');
      await expectCode(verifyTwilio({ ...forged, ...json }), 'signature_mismatch');
      // Ending the planted value with "#" to hide the rest in a fragment fails too.
      const hidden = await signTwilio({
        payload: new URLSearchParams({
          AccountSid: 'AC123',
          Body: `&bodySHA256=${hash}#`,
          To: '+1',
        }).toString(),
        secret,
        url: configured,
      });
      await expectCode(
        verifyTwilio({
          payload: attackerBody,
          headers: hidden.headers,
          secret,
          url: `${configured}AccountSidAC123Body&bodySHA256=${hash}#To+1`,
          ...json,
        }),
        'signature_mismatch',
      );
    });

    it('signTwilio refuses a #fragment, which a request URL never carries', async () => {
      await expect(
        signTwilio({ payload: body, secret, url: 'https://example.com/h#f', ...json }),
      ).rejects.toThrow(/fragment/);
    });
  });

  it('documents a protocol property: the signature covers the concatenation, not the split', async () => {
    // Twilio joins names and values without delimiters and drops repeated
    // values, so re-splitting the same characters into other parameters, or
    // repeating one, still verifies. Handlers must validate the parameters
    // they read (see the README section on Twilio).
    const url = 'https://example.com/sms';
    const signed = await signTwilio({ payload: 'Body=hi&From=%2B1555&To=%2B1666', secret, url });
    for (const payload of [
      'Body=hiFrom%2B1555&To=%2B1666',
      'Bo=dyhi&From=%2B1555&To=%2B1666',
      'Body=hi&Body=hi&From=%2B1555&To=%2B1666',
    ]) {
      await expect(
        verifyTwilio({ payload, headers: signed.headers, secret, url }),
      ).resolves.toBeDefined();
    }
  });

  it('signs without URL credentials, as Twilio does, but returns the URL with them', async () => {
    const url = 'https://user:pass@example.com/sms';
    const signed = await signTwilio({ payload: form, secret, url });
    expect(signed.url).toBe(url);
    expect(signed.headers).toEqual(
      (await signTwilio({ payload: form, secret, url: 'https://example.com/sms' })).headers,
    );
    for (const verifyUrl of [url, 'https://example.com/sms']) {
      await expect(
        verifyTwilio({ payload: form, headers: signed.headers, secret, url: verifyUrl }),
      ).resolves.toBeDefined();
    }
    const json = await signTwilio({ payload: '{}', secret, url, scheme: 'body-sha256' });
    await expect(
      verifyTwilio({
        payload: '{}',
        headers: json.headers,
        secret,
        url: json.url,
        scheme: 'body-sha256',
      }),
    ).resolves.toBeDefined();
  });

  it('rejects an unknown scheme with a TypeError', async () => {
    const scheme = 'json' as unknown as 'body-sha256';
    await expect(
      verifyTwilio({ payload: form, headers: {}, secret, url: 'https://example.com/', scheme }),
    ).rejects.toThrow(TypeError);
    await expect(
      signTwilio({ payload: form, secret, url: 'https://example.com/', scheme }),
    ).rejects.toThrow(TypeError);
  });

  it('rejects URLs that are not absolute http(s) URLs', async () => {
    const signed = await signTwilio({ payload: form, secret, url: 'https://example.com/sms' });
    for (const url of [
      '/sms',
      'example.com/sms',
      'ftp://example.com/sms',
      'https://',
      'https://exa mple.com/',
      42,
    ]) {
      await expect(
        verifyTwilio({ payload: form, headers: signed.headers, secret, url: url as string }),
      ).rejects.toThrow(TypeError);
    }
    await expect(signTwilio({ payload: form, secret, url: 'not a url' })).rejects.toThrow(
      TypeError,
    );
  });
});

describe('Paddle', () => {
  const secret = 'pdl_ntfset_01gkpjp8bkm3tm53kdgkx6sms7_secret';

  it("defaults to Paddle's 5 second tolerance", async () => {
    const headers = await signPaddle({ payload, secret, timestamp: NOW });
    await expect(
      verifyPaddle({ payload, headers, secret, now: shift(NOW, 5) }),
    ).resolves.toBeDefined();
    await expectCode(
      verifyPaddle({ payload, headers, secret, now: shift(NOW, 6) }),
      'timestamp_out_of_tolerance',
    );
    await expect(
      verifyPaddle({ payload, headers, secret, now: shift(NOW, 60), toleranceSeconds: 300 }),
    ).resolves.toEqual({ provider: 'paddle', timestamp: NOW });
  });

  it('formats the header like Paddle: ts first, then one h1 per secret', async () => {
    const headers = await signPaddle({ payload, secret: ['a', 'b'], timestamp: NOW });
    expect(headers['paddle-signature']).toMatch(/^ts=\d+;h1=[0-9a-f]{64};h1=[0-9a-f]{64}$/);
  });
});

describe('Lemon Squeezy', () => {
  it('returns the unsigned X-Event-Name header', async () => {
    const secret = 'lemon';
    const headers = {
      ...(await signLemonSqueezy({ payload, secret })),
      'X-Event-Name': 'order_created',
    };
    await expect(verifyLemonSqueezy({ payload, headers, secret })).resolves.toEqual({
      provider: 'lemon-squeezy',
      eventName: 'order_created',
    });
  });
});

describe('WebhookVerificationError', () => {
  it('is a well-formed Error subclass', async () => {
    const error = await expectCode(
      verifyGitHub({ payload, headers: {}, secret: 's' }),
      'missing_header',
    );
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('WebhookVerificationError');
    expect(error.provider).toBe('github');
    expect(error.stack).toBeTypeOf('string');
    expect(Object.prototype.toString.call(error)).toBe('[object Error]');
  });

  it('carries an optional cause', () => {
    const cause = new Error('root');
    const error = new WebhookVerificationError('malformed_header', 'msg', {
      provider: 'stripe',
      cause,
    });
    expect(error.cause).toBe(cause);
    expect(error.header).toBeUndefined();
    expect(
      'cause' in new WebhookVerificationError('malformed_header', 'msg', { provider: 'stripe' }),
    ).toBe(false);
  });
});
