import { describe, expect, it } from 'vitest';
import { concatBytes, payloadToBytes } from '../../../src/internal/bytes.js';

describe('payloadToBytes', () => {
  it('copies views, so later mutation of the caller buffer has no effect', () => {
    const source = new Uint8Array([1, 2, 3]);
    const bytes = payloadToBytes(source);
    source[0] = 9;
    expect([...bytes]).toEqual([1, 2, 3]);
  });

  it('accepts any ArrayBufferView, such as DataView', () => {
    const buffer = new Uint8Array([0, 1, 2, 3]).buffer;
    expect([...payloadToBytes(new DataView(buffer, 1, 2))]).toEqual([1, 2]);
  });

  it('encodes strings as UTF-8', () => {
    expect([...payloadToBytes('é✓')]).toEqual([0xc3, 0xa9, 0xe2, 0x9c, 0x93]);
  });

  it('explains what to do when given a parsed body', () => {
    expect(() => payloadToBytes({ id: 'evt_1' })).toThrow(/body parser/);
    expect(() => payloadToBytes([1, 2])).toThrow(/received array/);
    expect(() => payloadToBytes(null)).toThrow(/received null/);
  });
});

describe('concatBytes', () => {
  it('concatenates in order', () => {
    expect([...concatBytes(new Uint8Array([1]), new Uint8Array(), new Uint8Array([2, 3]))]).toEqual(
      [1, 2, 3],
    );
  });
});
