import type { Bytes } from './bytes.js';

const HEX_PATTERN = /^[0-9a-fA-F]*$/;
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

/** Lower-case hex encoding. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, '0');
  }
  return out;
}

/**
 * Decodes hex (either case). Returns `undefined` if the input is not hex or
 * does not decode to exactly `expectedLength` bytes.
 */
export function hexToBytes(hex: string, expectedLength: number): Bytes | undefined {
  if (hex.length !== expectedLength * 2 || !HEX_PATTERN.test(hex)) {
    return undefined;
  }
  const out = new Uint8Array(expectedLength);
  for (let i = 0; i < expectedLength; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Standard base64 encoding with padding (RFC 4648, section 4). */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/**
 * Decodes standard base64 (RFC 4648, section 4). Padding is optional, but no
 * other characters (whitespace, URL-safe alphabet) are accepted. Returns
 * `undefined` for invalid input, or when `expectedLength` is given and the
 * decoded length differs.
 */
export function base64ToBytes(base64: string, expectedLength?: number): Bytes | undefined {
  if (!BASE64_PATTERN.test(base64) || base64.length % 4 === 1) {
    return undefined;
  }
  const unpadded = base64.replace(/=+$/, '');
  // Padding, when present, must complete the final quantum exactly.
  if (unpadded.length !== base64.length && base64.length % 4 !== 0) {
    return undefined;
  }
  // The checks above leave only input that the forgiving-base64 decoder
  // behind atob() accepts, so it cannot throw here.
  const binary = atob(unpadded);
  if (expectedLength !== undefined && binary.length !== expectedLength) {
    return undefined;
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}
