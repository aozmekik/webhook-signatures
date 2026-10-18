/**
 * An independent oracle: each scheme re-implemented in a few lines with
 * node:crypto, straight from the provider's documentation, and compared with
 * the library's output over generated inputs. This is the only cross-check for
 * Lemon Squeezy, which ships no official verification SDK.
 */
import { createHash, createHmac } from 'node:crypto';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
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

const hmac = (algorithm: string, key: string | Buffer, message: Buffer | string) =>
  createHmac(algorithm, key).update(message);

const body = fc.uint8Array({ maxLength: 300 }).map((bytes) => Buffer.from(bytes));
const secret = fc.string({ minLength: 1, maxLength: 40, unit: 'grapheme' });
const seconds = fc.integer({ min: 1_000_000_000, max: 4_000_000_000 });

describe('node:crypto oracle', () => {
  it('Stripe: t=<ts>,v1=hex(HMAC-SHA256(secret, "<ts>." + body))', async () => {
    await fc.assert(
      fc.asyncProperty(body, secret, seconds, async (payload, key, ts) => {
        const expected = `t=${ts},v1=${hmac('sha256', key, Buffer.concat([Buffer.from(`${ts}.`), payload])).digest('hex')}`;
        const timestamp = new Date(ts * 1000);
        expect((await signStripe({ payload, secret: key, timestamp }))['stripe-signature']).toBe(
          expected,
        );
        await verifyStripe({
          payload,
          headers: { 'stripe-signature': expected },
          secret: key,
          now: timestamp,
        });
      }),
    );
  });

  it('GitHub: sha256=hex(HMAC-SHA256(secret, body))', async () => {
    await fc.assert(
      fc.asyncProperty(body, secret, async (payload, key) => {
        const expected = `sha256=${hmac('sha256', key, payload).digest('hex')}`;
        expect((await signGitHub({ payload, secret: key }))['x-hub-signature-256']).toBe(expected);
        await verifyGitHub({ payload, headers: { 'x-hub-signature-256': expected }, secret: key });
      }),
    );
  });

  it('Slack: v0=hex(HMAC-SHA256(secret, "v0:<ts>:" + body))', async () => {
    await fc.assert(
      fc.asyncProperty(body, secret, seconds, async (payload, key, ts) => {
        const expected = `v0=${hmac('sha256', key, Buffer.concat([Buffer.from(`v0:${ts}:`), payload])).digest('hex')}`;
        const timestamp = new Date(ts * 1000);
        const headers = { 'x-slack-signature': expected, 'x-slack-request-timestamp': String(ts) };
        expect(await signSlack({ payload, secret: key, timestamp })).toEqual(headers);
        await verifySlack({ payload, headers, secret: key, now: timestamp });
      }),
    );
  });

  it('Shopify: base64(HMAC-SHA256(secret, body))', async () => {
    await fc.assert(
      fc.asyncProperty(body, secret, async (payload, key) => {
        const expected = hmac('sha256', key, payload).digest('base64');
        expect((await signShopify({ payload, secret: key }))['x-shopify-hmac-sha256']).toBe(
          expected,
        );
        await verifyShopify({
          payload,
          headers: { 'x-shopify-hmac-sha256': expected },
          secret: key,
        });
      }),
    );
  });

  it('Standard Webhooks: v1,base64(HMAC-SHA256(base64decode(secret), "<id>.<ts>." + body))', async () => {
    const keyBytes = fc.uint8Array({ minLength: 24, maxLength: 64 }).map((b) => Buffer.from(b));
    const msgId = fc.stringMatching(/^msg_[A-Za-z0-9]{1,27}$/);
    await fc.assert(
      fc.asyncProperty(body, keyBytes, msgId, seconds, async (payload, key, id, ts) => {
        const signature = hmac(
          'sha256',
          key,
          Buffer.concat([Buffer.from(`${id}.${ts}.`), payload]),
        ).digest('base64');
        const headers = {
          'webhook-id': id,
          'webhook-timestamp': String(ts),
          'webhook-signature': `v1,${signature}`,
        };
        const whsec = `whsec_${key.toString('base64')}`;
        const timestamp = new Date(ts * 1000);
        expect(await signStandardWebhook({ payload, secret: whsec, id, timestamp })).toEqual(
          headers,
        );
        await verifyStandardWebhook({ payload, headers, secret: whsec, now: timestamp });
      }),
    );
  });

  it('Twilio: base64(HMAC-SHA1(token, url + sorted name+value pairs))', async () => {
    const params = fc.dictionary(
      fc.stringMatching(/^[A-Za-z][A-Za-z0-9]{0,10}$/),
      fc.string({ maxLength: 20 }),
      {
        maxKeys: 8,
      },
    );
    await fc.assert(
      fc.asyncProperty(params, secret, async (record, token) => {
        const url = 'https://example.com/hook?a=1';
        const names = Object.keys(record).sort();
        const signed = names.reduce((acc, name) => acc + name + (record[name] ?? ''), url);
        const expected = hmac('sha1', token, Buffer.from(signed, 'utf8')).digest('base64');
        const payload = new URLSearchParams(record).toString();
        expect(
          (await signTwilio({ payload, secret: token, url })).headers['x-twilio-signature'],
        ).toBe(expected);
        await verifyTwilio({
          payload,
          headers: { 'x-twilio-signature': expected },
          secret: token,
          url,
        });
      }),
    );
  });

  it('Twilio JSON: bodySHA256=hex(SHA-256(body)) in the signed URL', async () => {
    await fc.assert(
      fc.asyncProperty(body, secret, async (payload, token) => {
        const url = `https://example.com/hook?bodySHA256=${createHash('sha256').update(payload).digest('hex')}`;
        const expected = hmac('sha1', token, url).digest('base64');
        const signed = await signTwilio({
          payload,
          secret: token,
          url: 'https://example.com/hook',
          scheme: 'body-sha256',
        });
        expect(signed).toEqual({ url, headers: { 'x-twilio-signature': expected } });
        await verifyTwilio({
          payload,
          headers: signed.headers,
          secret: token,
          url,
          scheme: 'body-sha256',
        });
      }),
    );
  });

  it('Paddle: ts=<ts>;h1=hex(HMAC-SHA256(secret, "<ts>:" + body))', async () => {
    await fc.assert(
      fc.asyncProperty(body, secret, seconds, async (payload, key, ts) => {
        const expected = `ts=${ts};h1=${hmac('sha256', key, Buffer.concat([Buffer.from(`${ts}:`), payload])).digest('hex')}`;
        const timestamp = new Date(ts * 1000);
        expect((await signPaddle({ payload, secret: key, timestamp }))['paddle-signature']).toBe(
          expected,
        );
        await verifyPaddle({
          payload,
          headers: { 'paddle-signature': expected },
          secret: key,
          now: timestamp,
        });
      }),
    );
  });

  it('Lemon Squeezy: hex(HMAC-SHA256(secret, body))', async () => {
    await fc.assert(
      fc.asyncProperty(body, secret, async (payload, key) => {
        const expected = hmac('sha256', key, payload).digest('hex');
        expect((await signLemonSqueezy({ payload, secret: key }))['x-signature']).toBe(expected);
        await verifyLemonSqueezy({ payload, headers: { 'x-signature': expected }, secret: key });
      }),
    );
  });
});
