/** Cross-validation against the official Twilio helper library (twilio-node). */
import twilio from 'twilio';
import { describe, expect, it } from 'vitest';
import { verifyTwilio } from 'webhook-signatures';
import { signTwilio } from 'webhook-signatures/testing';
import { expectCode } from '../support/assertions.js';

const authToken = '12345abcdef12345abcdef12345abcde';

/** Parses a form body into the params object twilio-node expects (arrays for repeated names). */
function toParams(body: string): Record<string, string | string[]> {
  const params: Record<string, string | string[]> = {};
  for (const [name, value] of new URLSearchParams(body)) {
    const existing = params[name];
    params[name] =
      existing === undefined
        ? value
        : [...(Array.isArray(existing) ? existing : [existing]), value];
  }
  return params;
}

const cases = [
  {
    label: 'SMS callback',
    url: 'https://example.com/twilio/sms?tenant=acme&x=%20y',
    body: 'MessageSid=SM123&Body=Merhaba+d%C3%BCnya+%F0%9F%91%8B&From=%2B905551112233&To=%2B15005550006&NumMedia=0',
  },
  {
    label: 'repeated parameters',
    url: 'https://example.com/twilio/status',
    body: 'Tag=b&Tag=a&CallSid=CA1&Tag=c',
  },
  {
    label: 'GET with query only',
    url: 'https://example.com/voice?CallSid=CA1&From=%2B1',
    body: '',
  },
  {
    label: 'non-default port',
    url: 'https://example.com:8443/voice',
    body: 'CallSid=CA9&Digits=42',
  },
];

describe('twilio-node interop', () => {
  it.each(cases)(
    'twilio.validateRequest accepts signTwilio output ($label)',
    async ({ url, body }) => {
      const { headers } = await signTwilio({ payload: body, secret: authToken, url });
      const signature = headers['x-twilio-signature'] ?? '';
      expect(signature).toBe(twilio.getExpectedTwilioSignature(authToken, url, toParams(body)));
      expect(twilio.validateRequest(authToken, signature, url, toParams(body))).toBe(true);
    },
  );

  it.each(cases)('verifyTwilio accepts twilio-node signatures ($label)', async ({ url, body }) => {
    const signature = twilio.getExpectedTwilioSignature(authToken, url, toParams(body));
    await expect(
      verifyTwilio({
        payload: body,
        headers: { 'X-Twilio-Signature': signature },
        secret: authToken,
        url,
      }),
    ).resolves.toEqual({ provider: 'twilio', scheme: 'form-params' });
  });

  it('agree on the port fallbacks', async () => {
    // Signed with the port present, validated without it (and vice versa).
    const body = 'CallSid=CA1';
    const signature = twilio.getExpectedTwilioSignature(
      authToken,
      'https://example.com:443/voice',
      toParams(body),
    );
    expect(
      twilio.validateRequest(authToken, signature, 'https://example.com/voice', toParams(body)),
    ).toBe(true);
    await expect(
      verifyTwilio({
        payload: body,
        headers: { 'x-twilio-signature': signature },
        secret: authToken,
        url: 'https://example.com/voice',
      }),
    ).resolves.toBeDefined();
  });

  describe('JSON bodies', () => {
    const body = JSON.stringify({ CallSid: 'CA1234567890ABCDE', Caller: '+12349013030' });

    it('twilio.validateRequestWithBody accepts signTwilio output', async () => {
      const { url, headers } = await signTwilio({
        payload: body,
        secret: authToken,
        url: 'https://example.com/myapp',
        scheme: 'body-sha256',
      });
      expect(
        twilio.validateRequestWithBody(authToken, headers['x-twilio-signature'] ?? '', url, body),
      ).toBe(true);
    });

    it('verifyTwilio accepts twilio-node signatures', async () => {
      const url = `https://example.com/myapp?bodySHA256=${twilio.getExpectedBodyHash(body)}`;
      const signature = twilio.getExpectedTwilioSignature(authToken, url, {});
      await expect(
        verifyTwilio({
          payload: body,
          headers: { 'x-twilio-signature': signature },
          secret: authToken,
          url,
        }),
      ).resolves.toEqual({ provider: 'twilio', scheme: 'body-sha256' });
    });

    it('both reject a body that does not match bodySHA256', async () => {
      const url = `https://example.com/myapp?bodySHA256=${twilio.getExpectedBodyHash(body)}`;
      const signature = twilio.getExpectedTwilioSignature(authToken, url, {});
      const tampered = body.replace('CA1', 'CA2');
      expect(twilio.validateRequestWithBody(authToken, signature, url, tampered)).toBe(false);
      await expectCode(
        verifyTwilio({
          payload: tampered,
          headers: { 'x-twilio-signature': signature },
          secret: authToken,
          url,
        }),
        'signature_mismatch',
      );
    });
  });
});
