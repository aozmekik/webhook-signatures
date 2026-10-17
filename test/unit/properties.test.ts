/**
 * Property-based tests (fast-check): round trips and tamper detection over
 * generated bodies, secrets and timestamps, plus a parser fuzz that feeds
 * arbitrary header values to every verifier.
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { WebhookVerificationError, verifyTwilio } from 'webhook-signatures';
import { signTwilio } from 'webhook-signatures/testing';
import { NOW, expectCode } from '../support/assertions.js';
import { TWILIO_URL, providerCases } from '../support/providers.js';
import type { ProviderCase } from '../support/providers.js';

const byteLevelProviders = providerCases.filter((p) => p.id !== 'twilio');

function secretFor(provider: ProviderCase): fc.Arbitrary<string> {
  if (provider.id === 'standard-webhooks') {
    return fc
      .uint8Array({ minLength: 24, maxLength: 64 })
      .map((key) => `whsec_${btoa(String.fromCharCode(...key))}`);
  }
  return fc.string({ minLength: 1, maxLength: 64, unit: 'grapheme' });
}

const timestamps = fc.date({
  min: new Date('2001-09-09T01:46:40Z'),
  max: new Date('2100-01-01T00:00:00Z'),
  noInvalidDate: true,
});

describe.each(byteLevelProviders)('$id properties', (provider) => {
  it('verifies whatever it signs', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ maxLength: 512 }),
        secretFor(provider),
        timestamps,
        async (payload, secret, timestamp) => {
          const headers = await provider.sign({ payload, secret, timestamp });
          await provider.verify({ payload, headers, secret, now: timestamp });
        },
      ),
    );
  });

  it('detects any single-byte change to the body', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 256 }),
        fc.nat(),
        fc.integer({ min: 1, max: 255 }),
        secretFor(provider),
        async (payload, position, delta, secret) => {
          const headers = await provider.sign({ payload, secret, timestamp: NOW });
          const tampered = payload.slice();
          const index = position % tampered.length;
          tampered[index] = ((tampered[index] ?? 0) + delta) % 256;
          await expectCode(
            provider.verify({ payload: tampered, headers, secret, now: NOW }),
            'signature_mismatch',
          );
        },
      ),
      { numRuns: 50 },
    );
  });
});

describe('twilio properties', () => {
  const params = fc.dictionary(
    fc.string({ minLength: 1, maxLength: 12 }),
    fc.string({ maxLength: 24, unit: 'grapheme' }),
    { minKeys: 1, maxKeys: 8 },
  );

  it('verifies whatever form body it signs, in any parameter order', async () => {
    await fc.assert(
      fc.asyncProperty(params, fc.boolean(), async (record, reverse) => {
        const entries = Object.entries(record);
        const body = new URLSearchParams(entries).toString();
        const signed = await signTwilio({ payload: body, secret: 'token', url: TWILIO_URL });
        const sent = new URLSearchParams(reverse ? entries.reverse() : entries).toString();
        await verifyTwilio({
          payload: sent,
          headers: signed.headers,
          secret: 'token',
          url: signed.url,
        });
      }),
    );
  });

  it('detects a changed parameter value', async () => {
    await fc.assert(
      fc.asyncProperty(params, fc.string({ minLength: 1, maxLength: 4 }), async (record, extra) => {
        const entries = Object.entries(record);
        const body = new URLSearchParams(entries).toString();
        const signed = await signTwilio({ payload: body, secret: 'token', url: TWILIO_URL });
        const [first, ...rest] = entries;
        const changed = new URLSearchParams([
          [first?.[0] ?? '', `${first?.[1] ?? ''}${extra}`],
          ...rest,
        ]).toString();
        await expectCode(
          verifyTwilio({
            payload: changed,
            headers: signed.headers,
            secret: 'token',
            url: signed.url,
          }),
          'signature_mismatch',
        );
      }),
      { numRuns: 50 },
    );
  });
});

describe('parser fuzz', () => {
  const headerValue = fc.oneof(
    fc.string({ maxLength: 200, unit: 'binary' }),
    fc.stringMatching(/^(t|v1|v0|ts|h1)=[0-9a-f]{0,70}([,;](t|v1|ts|h1)=[0-9a-f]{0,70}){0,4}$/),
    fc.stringMatching(/^(v1|v1a),[A-Za-z0-9+/=]{0,50}( (v1|v1a),[A-Za-z0-9+/=]{0,50}){0,3}$/),
    fc.stringMatching(/^(sha256=|v0=)?[0-9a-fA-F]{0,70}$/),
  );

  it.each(providerCases)(
    '$id only ever rejects arbitrary headers with WebhookVerificationError',
    async (provider) => {
      const names = [
        provider.signatureHeader,
        provider.timestamp?.header ?? provider.signatureHeader,
        'webhook-id',
      ];
      await fc.assert(
        fc.asyncProperty(fc.tuple(headerValue, headerValue, headerValue), async (values) => {
          const headers: Record<string, string> = {};
          names.forEach((name, i) => (headers[name] = values[i] ?? ''));
          const outcome = await provider
            .verify({ payload: 'body', headers, secret: provider.secret, now: NOW })
            .then(
              () => 'verified',
              (error: unknown) => error,
            );
          // A random header cannot carry a valid HMAC; every failure must be typed.
          expect(outcome).toBeInstanceOf(WebhookVerificationError);
        }),
        { numRuns: 200 },
      );
    },
  );
});
