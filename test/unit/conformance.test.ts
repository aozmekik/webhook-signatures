/**
 * Behaviour every provider must share, checked once per provider.
 * Runs in both the Node and edge-runtime projects.
 */
import { describe, expect, it, vi } from 'vitest';
import { NOW, expectCode, shift, tamper, withHeader } from '../support/assertions.js';
import { providerCases } from '../support/providers.js';

describe.each(providerCases)('$id', (provider) => {
  const { secret, otherSecret, samplePayload: payload } = provider;
  const sign = (overrides: { secret?: string | string[]; payload?: string } = {}) =>
    provider.sign({
      payload: overrides.payload ?? payload,
      secret: overrides.secret ?? secret,
      timestamp: NOW,
    });

  it('accepts a request it signed', async () => {
    const headers = await sign();
    await expect(provider.verify({ payload, headers, secret, now: NOW })).resolves.toMatchObject({
      provider: provider.id,
    });
  });

  it('accepts string, Uint8Array, ArrayBuffer and offset views of the same body', async () => {
    const headers = await sign();
    const bytes = new TextEncoder().encode(payload);
    const padded = new Uint8Array(bytes.length + 8);
    padded.set(bytes, 4);
    const inputs = [payload, bytes, bytes.buffer, padded.subarray(4, 4 + bytes.length)];
    for (const input of inputs) {
      await expect(
        provider.verify({ payload: input, headers, secret, now: NOW }),
      ).resolves.toBeDefined();
    }
  });

  it('rejects a tampered body', async () => {
    const headers = await sign();
    await expectCode(
      provider.verify({ payload: tamper(payload), headers, secret, now: NOW }),
      'signature_mismatch',
    );
  });

  it('accepts an empty body when it was signed', async () => {
    const headers = await sign({ payload: '' });
    await expect(
      provider.verify({ payload: '', headers, secret, now: NOW }),
    ).resolves.toBeDefined();
  });

  it('verifies concurrent requests independently', async () => {
    // No shared mutable state: interleaved valid and forged requests each get
    // their own verdict.
    const bodies = Array.from({ length: 64 }, (_, i) => `${payload}${' '.repeat(i % 4)}`);
    const signed = await Promise.all(bodies.map((body) => sign({ payload: body })));
    const outcomes = await Promise.all(
      bodies.map((body, i) =>
        provider
          .verify({
            payload: i % 3 === 0 ? tamper(body) : body,
            headers: signed[i] ?? {},
            secret,
            now: NOW,
          })
          .then(
            () => 'ok',
            (error: unknown) => (error as { code?: string }).code,
          ),
      ),
    );
    expect(outcomes).toEqual(bodies.map((_, i) => (i % 3 === 0 ? 'signature_mismatch' : 'ok')));
  });

  it('does not mutate the caller payload or headers', async () => {
    const headers = await sign();
    const headersBefore = { ...headers };
    const bytes = new TextEncoder().encode(payload);
    const bytesBefore = [...bytes];
    await provider.verify({ payload: bytes, headers, secret, now: NOW });
    expect(headers).toEqual(headersBefore);
    expect([...bytes]).toEqual(bytesBefore);
  });

  it('rejects a body with an extra trailing newline', async () => {
    const headers = await sign();
    await expectCode(
      provider.verify({ payload: `${payload}\n`, headers, secret, now: NOW }),
      'signature_mismatch',
    );
  });

  it('rejects the wrong secret', async () => {
    const headers = await sign();
    await expectCode(
      provider.verify({ payload, headers, secret: otherSecret, now: NOW }),
      'signature_mismatch',
    );
  });

  it('accepts any secret from a rotation list', async () => {
    const headers = await sign({ secret: otherSecret });
    await expect(
      provider.verify({ payload, headers, secret: [secret, otherSecret], now: NOW }),
    ).resolves.toBeDefined();
    await expect(
      provider.verify({ payload, headers, secret: [otherSecret, secret], now: NOW }),
    ).resolves.toBeDefined();
  });

  it('hints at whitespace around a secret on mismatch', async () => {
    const headers = await sign();
    if (provider.id === 'standard-webhooks') {
      // A base64 secret with surrounding whitespace is rejected outright.
      await expectCode(
        provider.verify({ payload, headers, secret: `${secret}\n`, now: NOW }),
        'invalid_secret',
      );
      return;
    }
    const error = await expectCode(
      provider.verify({ payload, headers, secret: `${secret}\n`, now: NOW }),
      'signature_mismatch',
    );
    expect(error.message).toContain('whitespace');
    expect(error.message).not.toContain(secret);
  });

  if (provider.multiSignature) {
    it('emits and accepts one signature per secret', async () => {
      const headers = await sign({ secret: [otherSecret, secret] });
      await expect(provider.verify({ payload, headers, secret, now: NOW })).resolves.toBeDefined();
      await expect(
        provider.verify({ payload, headers, secret: otherSecret, now: NOW }),
      ).resolves.toBeDefined();
      await expectCode(
        provider.verify({ payload, headers, secret: 'whsec_dW5yZWxhdGVkLXNlY3JldA==', now: NOW }),
        'signature_mismatch',
      );
    });
  } else {
    it('signs with the first secret only, as the provider sends one signature', async () => {
      const headers = await sign({ secret: [secret, otherSecret] });
      await expect(provider.verify({ payload, headers, secret, now: NOW })).resolves.toBeDefined();
      await expectCode(
        provider.verify({ payload, headers, secret: otherSecret, now: NOW }),
        'signature_mismatch',
      );
    });
  }

  it('matches header names case-insensitively in plain records', async () => {
    const headers = await sign();
    const upper = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toUpperCase(), v]));
    const title = Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k.replace(/(^|-)\w/g, (s) => s.toUpperCase()), v]),
    );
    for (const variant of [upper, title]) {
      await expect(
        provider.verify({ payload, headers: variant, secret, now: NOW }),
      ).resolves.toBeDefined();
    }
  });

  it('accepts a Fetch API Headers object', async () => {
    const headers = new Headers(await sign());
    await expect(provider.verify({ payload, headers, secret, now: NOW })).resolves.toBeDefined();
  });

  it('accepts Node-style single-element header arrays and ignores unrelated headers', async () => {
    const signed = await sign();
    const headers: Record<string, string | string[] | undefined> = {
      'content-type': 'application/json',
      'x-unrelated': undefined,
    };
    for (const [name, value] of Object.entries(signed)) {
      headers[name] = [value];
    }
    await expect(provider.verify({ payload, headers, secret, now: NOW })).resolves.toBeDefined();
  });

  it('rejects two different values for the signature header', async () => {
    const signed = await sign();
    const other = await sign({ secret: otherSecret });
    const name = provider.signatureHeader;
    const headers = { ...signed, [name.toUpperCase()]: other[name] ?? '' };
    await expectCode(provider.verify({ payload, headers, secret, now: NOW }), 'malformed_header');
  });

  it('rejects a missing or blank signature header', async () => {
    const signed = await sign();
    for (const value of [undefined, '', '   ']) {
      const headers = withHeader(signed, provider.signatureHeader, value);
      const error = await expectCode(
        provider.verify({ payload, headers, secret, now: NOW }),
        'missing_header',
      );
      expect(error.provider).toBe(provider.id);
      expect(error.header).toBe(provider.signatureHeader);
    }
  });

  it('rejects unusable secrets', async () => {
    const headers = await sign();
    for (const bad of ['', [], [secret, ''], undefined, 42]) {
      await expectCode(
        provider.verify({ payload, headers, secret: bad as string, now: NOW }),
        'invalid_secret',
      );
    }
  });

  it('rejects payloads that are not raw bytes with a TypeError', async () => {
    const headers = await sign();
    for (const parsed of [JSON.parse('{"a":1}') as unknown, null, undefined, 7]) {
      await expect(
        provider.verify({ payload: parsed as string, headers, secret, now: NOW }),
      ).rejects.toThrow(TypeError);
    }
  });

  it('rejects headers that are not an object with a TypeError', async () => {
    await expect(
      provider.verify({ payload, headers: null as unknown as Headers, secret, now: NOW }),
    ).rejects.toThrow(TypeError);
  });

  const { timestamp } = provider;
  if (timestamp === undefined) {
    it('has no replay window: an old signature still verifies', async () => {
      const headers = await sign();
      await expect(
        provider.verify({ payload, headers, secret, now: shift(NOW, 365 * 24 * 3600) }),
      ).resolves.toBeDefined();
    });
    return;
  }

  describe('replay window', () => {
    const tolerance = timestamp.defaultToleranceSeconds;

    it(`defaults to ${tolerance}s, inclusive, in both directions`, async () => {
      const headers = await sign();
      for (const offset of [0, tolerance, -tolerance, tolerance - 0.5]) {
        await expect(
          provider.verify({ payload, headers, secret, now: shift(NOW, offset) }),
        ).resolves.toMatchObject({ timestamp: NOW });
      }
    });

    it('rejects expired timestamps', async () => {
      const headers = await sign();
      const error = await expectCode(
        provider.verify({ payload, headers, secret, now: shift(NOW, tolerance + 1) }),
        'timestamp_out_of_tolerance',
      );
      expect(error.message).toContain('too old');
      expect(error.header).toBe(timestamp.header);
    });

    it('rejects timestamps from the future', async () => {
      const headers = await sign();
      const error = await expectCode(
        provider.verify({ payload, headers, secret, now: shift(NOW, -(tolerance + 1)) }),
        'timestamp_out_of_tolerance',
      );
      expect(error.message).toContain('future');
    });

    it('honours a custom tolerance, including zero and Infinity', async () => {
      const headers = await sign();
      await expect(
        provider.verify({
          payload,
          headers,
          secret,
          now: shift(NOW, 3600),
          toleranceSeconds: 3600,
        }),
      ).resolves.toBeDefined();
      await expect(
        provider.verify({ payload, headers, secret, now: NOW, toleranceSeconds: 0 }),
      ).resolves.toBeDefined();
      await expectCode(
        provider.verify({ payload, headers, secret, now: shift(NOW, 1), toleranceSeconds: 0 }),
        'timestamp_out_of_tolerance',
      );
      await expect(
        provider.verify({
          payload,
          headers,
          secret,
          now: shift(NOW, 10 * 365 * 24 * 3600),
          toleranceSeconds: Infinity,
        }),
      ).resolves.toBeDefined();
    });

    it('checks the signature before the clock, so a forged stale request is a mismatch', async () => {
      const headers = await sign();
      await expectCode(
        provider.verify({ payload: tamper(payload), headers, secret, now: shift(NOW, 86_400) }),
        'signature_mismatch',
      );
    });

    it('defaults both signing time and verification clock to the current time', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      try {
        vi.setSystemTime(NOW);
        const headers = await provider.sign({ payload, secret });
        await expect(provider.verify({ payload, headers, secret })).resolves.toMatchObject({
          timestamp: NOW,
        });
        vi.setSystemTime(shift(NOW, tolerance + 1));
        await expectCode(
          provider.verify({ payload, headers, secret }),
          'timestamp_out_of_tolerance',
        );
      } finally {
        vi.useRealTimers();
      }
    });

    it('rejects invalid tolerance and clock options before doing any work', async () => {
      const headers = await sign();
      for (const toleranceSeconds of [-1, Number.NaN, '300' as unknown as number]) {
        await expect(
          provider.verify({ payload, headers, secret, now: NOW, toleranceSeconds }),
        ).rejects.toThrow(RangeError);
      }
      for (const now of [new Date(Number.NaN), 1_700_000_000 as unknown as Date]) {
        await expect(provider.verify({ payload, headers, secret, now })).rejects.toThrow(TypeError);
      }
    });
  });
});
