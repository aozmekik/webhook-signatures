/**
 * Lemon Squeezy webhook signatures.
 *
 * Scheme, per https://docs.lemonsqueezy.com/help/webhooks/signing-requests :
 *
 * - Header `X-Signature: <hex HMAC-SHA256 of the raw body>`, keyed with the
 *   signing secret chosen when the webhook was created.
 * - Lemon Squeezy signs no timestamp, so there is no replay window; see the
 *   README section on replay protection.
 *
 * @module
 */
import { payloadToBytes, utf8 } from '../internal/bytes.js';
import { hmacSign, hmacVerifyAny } from '../internal/crypto.js';
import { bytesToHex, hexToBytes } from '../internal/encoding.js';
import { malformedHeader, signatureMismatch } from '../internal/failures.js';
import { readHeader, requireHeader } from '../internal/headers.js';
import { readVerifyInput } from '../internal/input.js';
import { firstSecret } from '../internal/secrets.js';
import type { SignOptions, SignedHeaders, VerifyOptions } from '../types.js';

const PROVIDER = 'lemon-squeezy';
const HEADER = 'x-signature';

/** Options for {@link verifyLemonSqueezy}. `secret` is the webhook's signing secret. */
export type LemonSqueezyVerifyOptions = VerifyOptions;

/** A verified Lemon Squeezy webhook. */
export interface LemonSqueezyVerifyResult {
  readonly provider: 'lemon-squeezy';
  /**
   * `X-Event-Name` (for example `order_created`), if present. Not covered by
   * the signature; the same name is also inside the signed body.
   * @see https://docs.lemonsqueezy.com/help/webhooks/webhook-requests
   */
  readonly eventName: string | undefined;
}

/**
 * Verifies a Lemon Squeezy webhook (`X-Signature` header).
 *
 * @see https://docs.lemonsqueezy.com/help/webhooks/signing-requests
 * @throws {@link WebhookVerificationError} when verification fails.
 */
export async function verifyLemonSqueezy(
  options: LemonSqueezyVerifyOptions,
): Promise<LemonSqueezyVerifyResult> {
  const { payload, secrets } = readVerifyInput(options, PROVIDER);
  const signature = hexToBytes(requireHeader(options.headers, HEADER, PROVIDER, 'X-Signature'), 32);
  if (signature === undefined) {
    throw malformedHeader(PROVIDER, HEADER, 'X-Signature must be 64 hex characters');
  }
  if (!(await hmacVerifyAny(secrets.map(utf8), payload, [signature], 'SHA-256'))) {
    throw signatureMismatch(PROVIDER, HEADER, secrets);
  }
  return { provider: PROVIDER, eventName: readHeader(options.headers, 'x-event-name', PROVIDER) };
}

/** Options for {@link signLemonSqueezy}. Only the first secret is used. */
export type LemonSqueezySignOptions = SignOptions;

/** **Test utility.** Produces an `X-Signature` header for `payload`. */
export async function signLemonSqueezy(options: LemonSqueezySignOptions): Promise<SignedHeaders> {
  const secret = utf8(firstSecret(options.secret, PROVIDER));
  const signature = await hmacSign(secret, payloadToBytes(options.payload), 'SHA-256');
  return { [HEADER]: bytesToHex(signature) };
}
