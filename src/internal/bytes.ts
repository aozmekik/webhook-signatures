/** A byte array backed by a plain `ArrayBuffer`, as Web Crypto expects. */
export type Bytes = Uint8Array<ArrayBuffer>;

const encoder = /* @__PURE__ */ new TextEncoder();

/** Encodes a string as UTF-8. */
export function utf8(text: string): Bytes {
  return encoder.encode(text);
}

function describe(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return 'array';
  }
  return typeof value;
}

/**
 * Converts the raw request body into bytes.
 *
 * Accepts strings, `ArrayBuffer`s and any `ArrayBufferView` (`Uint8Array`,
 * Node.js `Buffer`, `DataView`, ...). The checks avoid `instanceof` so that
 * values created in another realm (a `vm` context, an iframe) still work.
 * The result is always a fresh copy, so a caller mutating its buffer
 * mid-verification cannot affect the outcome.
 *
 * @throws TypeError when the payload is not raw body data, which almost always
 *   means a body parser ran before verification.
 */
export function payloadToBytes(payload: unknown): Bytes {
  if (typeof payload === 'string') {
    return utf8(payload);
  }
  if (ArrayBuffer.isView(payload)) {
    const view = new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength);
    return new Uint8Array(view);
  }
  if (Object.prototype.toString.call(payload) === '[object ArrayBuffer]') {
    return new Uint8Array(new Uint8Array(payload as ArrayBuffer));
  }
  throw new TypeError(
    `payload must be the raw request body as a string, Uint8Array or ArrayBuffer, but received ${describe(payload)}. ` +
      'If a JSON or form body parser already ran, read the raw body instead (see the README recipes).',
  );
}

/** Concatenates byte arrays into a new array. */
export function concatBytes(...parts: readonly Uint8Array[]): Bytes {
  let length = 0;
  for (const part of parts) {
    length += part.byteLength;
  }
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}
