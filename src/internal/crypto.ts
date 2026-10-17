import type { Bytes } from './bytes.js';

/** Hash functions used by the supported HMAC schemes. */
export type HmacHash = 'SHA-256' | 'SHA-1';

/**
 * Upper bound on candidate signatures read from a single header.
 *
 * Every candidate costs one HMAC over the whole payload, so an attacker who
 * could list hundreds of signatures would turn one request into hundreds of
 * hash computations. Providers send one signature per active secret (two
 * during a rotation), so this limit is far above legitimate use.
 */
export const MAX_SIGNATURES_PER_HEADER = 10;

function subtle(): SubtleCrypto {
  const webCrypto = (globalThis as { crypto?: Crypto }).crypto;
  if (webCrypto?.subtle === undefined) {
    throw new Error(
      'webhook-signatures requires the Web Crypto API (globalThis.crypto.subtle), ' +
        'which Node.js, Deno, Bun, Cloudflare Workers and Vercel Edge all provide.',
    );
  }
  return webCrypto.subtle;
}

function importHmacKey(secret: Bytes, hash: HmacHash, usage: KeyUsage): Promise<CryptoKey> {
  return subtle().importKey('raw', secret, { name: 'HMAC', hash }, false, [usage]);
}

/** Computes an HMAC tag. Used by the signing helpers. */
export async function hmacSign(secret: Bytes, message: Bytes, hash: HmacHash): Promise<Bytes> {
  const key = await importHmacKey(secret, hash, 'sign');
  return new Uint8Array(await subtle().sign('HMAC', key, message));
}

/**
 * Returns `true` if any candidate signature is a valid HMAC of `message` under
 * any of the secrets.
 *
 * Comparison is delegated to `crypto.subtle.verify`, which compares tags in
 * constant time natively; no hand-written comparison loop is involved. The
 * loop stops at the first match: which (secret, signature) pair matched is not
 * secret, only the tag bytes are.
 */
export async function hmacVerifyAny(
  secrets: readonly Bytes[],
  message: Bytes,
  signatures: readonly Bytes[],
  hash: HmacHash,
): Promise<boolean> {
  for (const secret of secrets) {
    const key = await importHmacKey(secret, hash, 'verify');
    for (const signature of signatures) {
      if (await subtle().verify('HMAC', key, signature, message)) {
        return true;
      }
    }
  }
  return false;
}

/** SHA-256 digest. Used for Twilio's `bodySHA256` check. */
export async function sha256(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle().digest('SHA-256', data));
}
