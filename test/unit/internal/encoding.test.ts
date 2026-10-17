import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  hexToBytes,
} from '../../../src/internal/encoding.js';

describe('hex', () => {
  it('encodes lower-case and decodes either case', () => {
    const bytes = new Uint8Array([0, 1, 0x7f, 0x80, 0xab, 0xff]);
    expect(bytesToHex(bytes)).toBe('00017f80abff');
    expect(hexToBytes('00017F80ABFF', 6)).toEqual(bytes);
  });

  it.each([
    ['odd length', 'abc', 2],
    ['wrong length', 'abcd', 3],
    ['non-hex', 'zz', 1],
    ['sign', '-1', 1],
    ['whitespace', ' a', 1],
  ])('rejects %s', (_label, input, length) => {
    expect(hexToBytes(input, length)).toBeUndefined();
  });

  it('round-trips arbitrary bytes', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (bytes) => {
        expect(hexToBytes(bytesToHex(bytes), bytes.length)).toEqual(bytes);
      }),
    );
  });
});

describe('base64', () => {
  it('matches RFC 4648 test vectors', () => {
    // RFC 4648, section 10.
    const vectors: [string, string][] = [
      ['', ''],
      ['f', 'Zg=='],
      ['fo', 'Zm8='],
      ['foo', 'Zm9v'],
      ['foob', 'Zm9vYg=='],
      ['fooba', 'Zm9vYmE='],
      ['foobar', 'Zm9vYmFy'],
    ];
    for (const [plain, encoded] of vectors) {
      const bytes = new TextEncoder().encode(plain);
      expect(bytesToBase64(bytes)).toBe(encoded);
      expect(base64ToBytes(encoded)).toEqual(bytes);
      expect(base64ToBytes(encoded.replace(/=+$/, ''))).toEqual(bytes);
    }
  });

  it.each([
    ['URL-safe characters', 'ab-_'],
    ['whitespace', 'Zm9v Yg=='],
    ['padding in the middle', 'Zg==Zg=='],
    ['three padding characters', 'Z==='],
    ['impossible length', 'Zm9vY'],
    ['padding that does not complete a quantum', 'Zm9vY='],
  ])('rejects %s', (_label, input) => {
    expect(base64ToBytes(input)).toBeUndefined();
  });

  it('enforces an expected length', () => {
    expect(base64ToBytes('Zm9v', 3)).toEqual(new TextEncoder().encode('foo'));
    expect(base64ToBytes('Zm9v', 4)).toBeUndefined();
  });

  it('round-trips arbitrary bytes', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 96 }), (bytes) => {
        expect(base64ToBytes(bytesToBase64(bytes), bytes.length)).toEqual(bytes);
      }),
    );
  });

  it('never throws on arbitrary input', () => {
    fc.assert(
      fc.property(
        fc.oneof(fc.string({ unit: 'binary' }), fc.stringMatching(/^[A-Za-z0-9+/=]{0,12}$/)),
        (input) => {
          const decoded = base64ToBytes(input);
          if (decoded !== undefined) {
            expect(bytesToBase64(decoded).replace(/=+$/, '')).toHaveLength(
              input.replace(/=+$/, '').length,
            );
          }
        },
      ),
      { numRuns: 1000 },
    );
  });
});
