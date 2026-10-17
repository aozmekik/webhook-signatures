/**
 * Known-answer tests: signatures published in the providers' own
 * documentation (or reference test suites), recomputed independently.
 * Each vector cites its source.
 */
import { describe, expect, it } from 'vitest';
import { verifyGitHub, verifySlack, verifyStandardWebhook, verifyTwilio } from 'webhook-signatures';
import { signGitHub, signSlack, signStandardWebhook, signTwilio } from 'webhook-signatures/testing';

describe('GitHub documentation vector', () => {
  // https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#testing-the-webhook-payload-validation
  const secret = "It's a Secret to Everybody";
  const payload = 'Hello, World!';
  const signature = 'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17';

  it('signs to the documented value', async () => {
    expect(await signGitHub({ payload, secret })).toEqual({ 'x-hub-signature-256': signature });
  });

  it('verifies the documented value', async () => {
    await expect(
      verifyGitHub({ payload, secret, headers: { 'X-Hub-Signature-256': signature } }),
    ).resolves.toEqual({ provider: 'github', deliveryId: undefined, event: undefined });
  });
});

describe('Slack documentation vector', () => {
  // https://docs.slack.dev/authentication/verifying-requests-from-slack (step-by-step walkthrough)
  const secret = '8f742231b10e8888abcd99yyyzzz85a5';
  const timestamp = '1531420618';
  const payload =
    'token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V' +
    '&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=' +
    '&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN' +
    '&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c';
  const signature = 'v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503';
  const signedAt = new Date(Number(timestamp) * 1000);

  it('signs to the documented value', async () => {
    expect(await signSlack({ payload, secret, timestamp: signedAt })).toEqual({
      'x-slack-request-timestamp': timestamp,
      'x-slack-signature': signature,
    });
  });

  it('verifies the documented value', async () => {
    const headers = { 'X-Slack-Request-Timestamp': timestamp, 'X-Slack-Signature': signature };
    await expect(verifySlack({ payload, headers, secret, now: signedAt })).resolves.toEqual({
      provider: 'slack',
      timestamp: signedAt,
    });
  });
});

describe('Twilio documentation vector', () => {
  // https://www.twilio.com/docs/usage/security#explore-the-algorithm-yourself
  const secret = '12345';
  const url = 'https://example.com/myapp.php?foo=1&bar=2';
  // The documented POST parameters, form-encoded as Twilio sends them.
  const payload =
    'Digits=1234&To=%2B18005551212&From=%2B14158675310&Caller=%2B14158675310&CallSid=CA1234567890ABCDE';
  const signature = 'L/OH5YylLD5NRKLltdqwSvS0BnU=';

  it('signs to the documented value', async () => {
    expect(await signTwilio({ payload, secret, url })).toEqual({
      url,
      headers: { 'x-twilio-signature': signature },
    });
  });

  it('verifies the documented value', async () => {
    await expect(
      verifyTwilio({ payload, secret, url, headers: { 'X-Twilio-Signature': signature } }),
    ).resolves.toEqual({ provider: 'twilio', scheme: 'form-params' });
  });

  it('computes the documented bodySHA256 for the JSON example', async () => {
    // https://www.twilio.com/docs/usage/webhooks/webhooks-security (JSON body example)
    const body = '{"CallSid":"CA1234567890ABCDE","Caller":"+12349013030"}';
    const signed = await signTwilio({
      payload: body,
      secret,
      url: 'https://example.com/myapp',
      scheme: 'body-sha256',
    });
    expect(signed.url).toBe(
      'https://example.com/myapp?bodySHA256=5ccde7145dfb8f56479710896586cb9d5911809d83afbe34627818790db0aec9',
    );
  });
});

describe('Standard Webhooks / Svix vectors', () => {
  const vectors = [
    {
      // https://docs.svix.com/receiving/verifying-payloads/how-manual
      source: 'Svix manual verification guide',
      secret: 'whsec_plJ3nmyCDGBKInavdOK15jsl',
      id: 'msg_loFOjxBNrRLzqYUf',
      timestamp: '1731705121',
      payload: '{"event_type":"ping","data":{"success":true}}',
      signature: 'v1,rAvfW3dJ/X/qxhsaXPOyyCGmRKsaKWcsNccKXlIktD0=',
    },
    {
      // https://github.com/standard-webhooks/standard-webhooks/blob/main/libraries/javascript/src/webhook.test.ts
      source: 'standard-webhooks reference test suite',
      secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
      id: 'msg_p5jXN8AQM9LWM0D4loKWxJek',
      timestamp: '1614265330',
      payload: '{"test": 2432232314}',
      signature: 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=',
    },
  ];

  it.each(vectors)('signs the $source vector', async (v) => {
    const signed = await signStandardWebhook({
      payload: v.payload,
      secret: v.secret,
      id: v.id,
      timestamp: new Date(Number(v.timestamp) * 1000),
      headerPrefix: 'svix',
    });
    expect(signed).toEqual({
      'svix-id': v.id,
      'svix-timestamp': v.timestamp,
      'svix-signature': v.signature,
    });
  });

  it.each(vectors)('verifies the $source vector with webhook-* and svix-* headers', async (v) => {
    const now = new Date(Number(v.timestamp) * 1000);
    for (const prefix of ['webhook', 'svix']) {
      const headers = {
        [`${prefix}-id`]: v.id,
        [`${prefix}-timestamp`]: v.timestamp,
        [`${prefix}-signature`]: v.signature,
      };
      await expect(
        verifyStandardWebhook({ payload: v.payload, headers, secret: v.secret, now }),
      ).resolves.toEqual({ provider: 'standard-webhooks', id: v.id, timestamp: now });
    }
  });
});
