import { describe, expect, it } from 'vitest';
import { WebhookVerificationError } from 'webhook-signatures';
import { readHeader, requireHeader } from '../../../src/internal/headers.js';

describe('readHeader', () => {
  it('reads Headers objects case-insensitively', () => {
    const headers = new Headers({ 'Stripe-Signature': 't=1' });
    expect(readHeader(headers, 'stripe-signature', 'stripe')).toBe('t=1');
  });

  it('reads any object with a get method (polyfills, other realms)', () => {
    const headers = { get: (name: string) => (name === 'x-signature' ? ' abc ' : null) };
    expect(readHeader(headers as unknown as Headers, 'x-signature', 'lemon-squeezy')).toBe('abc');
    expect(readHeader(headers as unknown as Headers, 'x-other', 'lemon-squeezy')).toBeUndefined();
  });

  it('trims HTTP whitespace (spaces and tabs) only', () => {
    expect(readHeader({ a: ' \tv\t ' }, 'a', 'github')).toBe('v');
    expect(readHeader({ a: ' v' }, 'a', 'github')).toBe(' v');
  });

  it('keeps interior whitespace and treats whitespace-only values as blank', () => {
    expect(readHeader({ a: 'v \t w' }, 'a', 'github')).toBe('v \t w');
    expect(readHeader({ a: '\t' }, 'a', 'github')).toBeUndefined();
  });

  it('trims in linear time, even around a long interior run of whitespace', () => {
    // Regression test: a backtracking trim regex took seconds on 32 KB of
    // interior spaces and grew quadratically. A megabyte takes a few
    // milliseconds with the linear scan; the budget is two orders of
    // magnitude above that and three below the quadratic behaviour.
    const value = `a${' \t'.repeat(500_000)}b`;
    const start = performance.now();
    expect(readHeader({ a: ` ${value} ` }, 'a', 'github')).toBe(value);
    expect(readHeader(new Headers({ a: value }), 'a', 'github')).toBe(value);
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('rejects a Map, whose get() is case-sensitive, with a TypeError', () => {
    const headers = new Map([['X-Hub-Signature-256', 'sha256=00']]);
    expect(() =>
      readHeader(headers as unknown as Headers, 'x-hub-signature-256', 'github'),
    ).toThrow(/not a Map/);
  });

  it('treats blank, undefined and empty arrays as absent', () => {
    for (const value of ['', ' ', undefined, [], ['', ' ']]) {
      expect(readHeader({ a: value }, 'a', 'github')).toBeUndefined();
    }
  });

  it('accepts duplicates that agree and rejects ones that differ', () => {
    expect(readHeader({ A: 'v', a: 'v', 'a ': 'ignored' }, 'a', 'github')).toBe('v');
    expect(readHeader({ a: ['v', ' v'] }, 'a', 'github')).toBe('v');
    for (const headers of [{ A: 'v', a: 'w' }, { a: ['v', 'w'] }]) {
      expect(() => readHeader(headers, 'a', 'github')).toThrow(WebhookVerificationError);
    }
  });

  it('rejects values that are not strings', () => {
    for (const value of [1, true, {}, [1]]) {
      expect(() => readHeader({ a: value as unknown as string }, 'a', 'github')).toThrow(TypeError);
    }
    expect(() => readHeader('a: b' as unknown as Headers, 'a', 'github')).toThrow(TypeError);
  });

  it('ignores null values that some frameworks produce', () => {
    expect(readHeader({ a: null as unknown as string }, 'a', 'github')).toBeUndefined();
  });

  it('requireHeader names the header in the error', () => {
    try {
      requireHeader({}, 'x-signature', 'lemon-squeezy', 'X-Signature');
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(WebhookVerificationError);
      expect(error).toMatchObject({
        code: 'missing_header',
        header: 'x-signature',
        provider: 'lemon-squeezy',
        message: 'Missing X-Signature header',
      });
    }
  });
});
