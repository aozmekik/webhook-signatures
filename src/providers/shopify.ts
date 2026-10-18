/**
 * Shopify webhook signatures.
 *
 * Scheme, per https://shopify.dev/docs/apps/build/webhooks/subscribe/https :
 *
 * - Header `X-Shopify-Hmac-SHA256: <base64 HMAC-SHA256 of the raw body>`,
 *   keyed with the app's client secret as UTF-8.
 * - Shopify signs no timestamp, so there is no replay window. Shopify
 *   recommends de-duplicating on `X-Shopify-Webhook-Id`.
 * - After a secret rotation Shopify may keep signing with the old secret for
 *   up to an hour; pass both secrets as a list during that window.
 *
 * @module
 */
import { payloadToBytes, utf8 } from '../internal/bytes.js';
import { hmacSign, hmacVerifyAny } from '../internal/crypto.js';
import { base64ToBytes, bytesToBase64 } from '../internal/encoding.js';
import { malformedHeader, signatureMismatch } from '../internal/failures.js';
import { readHeader, requireHeader } from '../internal/headers.js';
import { readVerifyInput } from '../internal/input.js';
import { firstSecret } from '../internal/secrets.js';
import type { SignOptions, SignedHeaders, VerifyOptions } from '../types.js';

const PROVIDER = 'shopify';
const HEADER = 'x-shopify-hmac-sha256';

/** Options for {@link verifyShopify}. `secret` is the app's client secret. */
export type ShopifyVerifyOptions = VerifyOptions;

/** A verified Shopify webhook. */
export interface ShopifyVerifyResult {
  readonly provider: 'shopify';
  /**
   * `X-Shopify-Webhook-Id`, if present. Shopify recommends storing it to drop
   * duplicate deliveries. Not covered by the signature.
   * @see https://shopify.dev/docs/apps/build/webhooks
   */
  readonly webhookId: string | undefined;
  /** `X-Shopify-Topic` (for example `orders/create`), if present. Not covered by the signature. */
  readonly topic: string | undefined;
}

/**
 * Verifies a Shopify webhook (`X-Shopify-Hmac-SHA256` header).
 *
 * @see https://shopify.dev/docs/apps/build/webhooks/subscribe/https
 * @throws {@link WebhookVerificationError} when verification fails.
 */
export async function verifyShopify(options: ShopifyVerifyOptions): Promise<ShopifyVerifyResult> {
  const { payload, secrets } = readVerifyInput(options, PROVIDER);
  const value = requireHeader(options.headers, HEADER, PROVIDER, 'X-Shopify-Hmac-SHA256');
  const signature = base64ToBytes(value, 32);
  if (signature === undefined) {
    throw malformedHeader(
      PROVIDER,
      HEADER,
      'X-Shopify-Hmac-SHA256 is not a base64 HMAC-SHA256 digest',
    );
  }
  if (!(await hmacVerifyAny(secrets.map(utf8), payload, [signature], 'SHA-256'))) {
    throw signatureMismatch(PROVIDER, HEADER, secrets);
  }
  return {
    provider: PROVIDER,
    webhookId: readHeader(options.headers, 'x-shopify-webhook-id', PROVIDER),
    topic: readHeader(options.headers, 'x-shopify-topic', PROVIDER),
  };
}

/** Options for {@link signShopify}. Only the first secret is used. */
export type ShopifySignOptions = SignOptions;

/** **Test utility.** Produces an `X-Shopify-Hmac-SHA256` header for `payload`. */
export async function signShopify(
  options: ShopifySignOptions,
): Promise<SignedHeaders<'x-shopify-hmac-sha256'>> {
  const secret = utf8(firstSecret(options.secret, PROVIDER));
  const signature = await hmacSign(secret, payloadToBytes(options.payload), 'SHA-256');
  return { [HEADER]: bytesToBase64(signature) };
}
