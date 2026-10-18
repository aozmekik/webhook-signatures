import { describe, expect, it } from 'vitest';
import { WebhookVerificationError } from 'webhook-signatures';
import { captureHeaders } from '../../../src/internal/headers.js';

/** Captures header `a` from `headers` and returns its value. */
function readA(headers: unknown): string | undefined {
  return captureHeaders(headers, ['a'], 'github').get('a');
}

describe('captureHeaders', () => {
  it('reads Headers objects case-insensitively', () => {
    const headers = new Headers({ 'Stripe-Signature': 't=1' });
    expect(captureHeaders(headers, ['stripe-signature'], 'stripe').get('stripe-signature')).toBe(
      't=1',
    );
  });

  it('reads any object with a get method (polyfills, other realms)', () => {
    const headers = { get: (name: string) => (name === 'x-signature' ? ' abc ' : null) };
    const captured = captureHeaders(headers, ['x-signature', 'x-other'], 'lemon-squeezy');
    expect(captured.get('x-signature')).toBe('abc');
    expect(captured.get('x-other')).toBeUndefined();
  });

  it('reads plain records case-insensitively', () => {
    expect(readA({ A: 'v' })).toBe('v');
  });

  it('trims HTTP whitespace (spaces and tabs) only', () => {
    expect(readA({ a: ' \tv\t ' })).toBe('v');
    // A no-break space is not HTTP whitespace.
    expect(readA({ a: '\u00a0v' })).toBe('\u00a0v');
  });

  it('keeps interior whitespace and treats whitespace-only values as blank', () => {
    expect(readA({ a: 'v \t w' })).toBe('v \t w');
    expect(readA({ a: '\t' })).toBeUndefined();
  });

  it('trims in linear time, even around a long interior run of whitespace', () => {
    // Regression test: a backtracking trim regex took seconds on 32 KB of
    // interior spaces and grew quadratically. A megabyte takes a few
    // milliseconds with the linear scan; the budget is two orders of
    // magnitude above that and three below the quadratic behaviour.
    const value = `a${' \t'.repeat(500_000)}b`;
    const start = performance.now();
    expect(readA({ a: ` ${value} ` })).toBe(value);
    expect(readA(new Headers({ a: value }))).toBe(value);
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('rejects headers that are not an object with a TypeError', () => {
    for (const headers of [null, undefined, 'a: b', 1]) {
      expect(() => readA(headers)).toThrow(TypeError);
    }
  });

  it('rejects a Map, whose get() is case-sensitive, with a TypeError', () => {
    const headers = new Map([['X-Hub-Signature-256', 'sha256=00']]);
    expect(() => captureHeaders(headers, ['x-hub-signature-256'], 'github')).toThrow(/not a Map/);
  });

  it('treats blank, undefined and empty arrays as absent', () => {
    for (const value of ['', ' ', undefined, [], ['', ' ']]) {
      expect(readA({ a: value })).toBeUndefined();
    }
  });

  it('ignores null values that some frameworks produce', () => {
    expect(readA({ a: null })).toBeUndefined();
  });

  it('accepts duplicates that agree and rejects ones that differ', () => {
    expect(readA({ A: 'v', a: 'v', 'a ': 'ignored' })).toBe('v');
    expect(readA({ a: ['v', ' v'] })).toBe('v');
    for (const headers of [{ A: 'v', a: 'w' }, { a: ['v', 'w'] }]) {
      expect(() => readA(headers)).toThrow(WebhookVerificationError);
    }
  });

  it('reports differing duplicates on lookup, not on capture', () => {
    // malformed_header is a verification failure, so it must come after the
    // secret check; only type errors are raised by the capture itself.
    const captured = captureHeaders({ a: ['v', 'w'] }, ['a'], 'github');
    try {
      captured.get('a');
      expect.unreachable();
    } catch (error) {
      expect(error).toMatchObject({
        code: 'malformed_header',
        header: 'a',
        provider: 'github',
        message: 'Header "a" was sent more than once with different values',
      });
    }
  });

  it('rejects values of captured headers that are not strings, on capture', () => {
    for (const value of [1, true, {}, [1], ['v', 2], [['v']], () => 'v']) {
      expect(() => captureHeaders({ A: value }, ['a'], 'github')).toThrow(
        new TypeError('header "a" must be a string or an array of strings'),
      );
    }
    const polyfill = { get: () => 42 };
    expect(() => captureHeaders(polyfill, ['a'], 'github')).toThrow(TypeError);
  });

  it('never inspects headers that were not named', () => {
    const captured = captureHeaders({ a: 'v', b: 1, c: [{}] }, ['a'], 'github');
    expect(captured.get('a')).toBe('v');
  });

  it('getRequired returns the value, or names the header in the error', () => {
    const captured = captureHeaders({ 'X-Signature': ' abc' }, ['x-signature'], 'lemon-squeezy');
    expect(captured.getRequired('x-signature', 'X-Signature')).toBe('abc');
    try {
      captureHeaders({}, ['x-signature'], 'lemon-squeezy').getRequired(
        'x-signature',
        'X-Signature',
      );
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
