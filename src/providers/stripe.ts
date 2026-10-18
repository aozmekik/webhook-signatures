/**
 * Stripe webhook signatures.
 *
 * Scheme, per https://docs.stripe.com/webhooks?verify=verify-manually#verify-manually :
 *
 * - Header `Stripe-Signature: t=<unix seconds>,v1=<hex>[,v1=<hex>...]`.
 *   Stripe adds one `v1` per active secret while a secret is being rolled,
 *   and a fake `v0` for test events; every scheme other than `v1` is ignored,
 *   as the docs instruct, to prevent downgrade attacks.
 * - Signed payload: `<t>.<raw body>`.
 * - HMAC-SHA256 keyed with the endpoint secret (`whsec_...`), used verbatim.
 * - Stripe's libraries default to a 300 second tolerance; so does this one.
 *
 * @module
 */
import { concatBytes, payloadToBytes, utf8 } from '../internal/bytes.js';
import type { Bytes } from '../internal/bytes.js';
import { MAX_SIGNATURES_PER_HEADER, hmacSign, hmacVerifyAny } from '../internal/crypto.js';
import { bytesToHex, hexToBytes } from '../internal/encoding.js';
import { assertSignatureCount, malformedHeader, signatureMismatch } from '../internal/failures.js';
import { readVerifyInput } from '../internal/input.js';
import { parseKeyValueList } from '../internal/parse.js';
import { secretList } from '../internal/secrets.js';
import {
  assertFresh,
  parseUnixSeconds,
  resolveTolerance,
  toUnixSeconds,
} from '../internal/timestamp.js';
import type {
  SignOptions,
  SignTimestampOptions,
  SignedHeaders,
  TimestampToleranceOptions,
  VerifyOptions,
} from '../types.js';

const PROVIDER = 'stripe';
const HEADER = 'stripe-signature';
const DEFAULT_TOLERANCE_SECONDS = 300;

/** Options for {@link verifyStripe}. `secret` is the endpoint's `whsec_...` signing secret. */
export interface StripeVerifyOptions extends VerifyOptions, TimestampToleranceOptions {}

/** A verified Stripe webhook. */
export interface StripeVerifyResult {
  readonly provider: 'stripe';
  /** The signed `t` timestamp. */
  readonly timestamp: Date;
}

interface ParsedStripeHeader {
  readonly timestampText: string;
  readonly timestamp: number;
  readonly signatures: readonly Bytes[];
}

function parseHeader(value: string): ParsedStripeHeader {
  let timestampText: string | undefined;
  const signatures: Bytes[] = [];
  for (const [key, item] of parseKeyValueList(value, ',', PROVIDER, HEADER)) {
    if (key === 't') {
      if (timestampText !== undefined) {
        throw malformedHeader(
          PROVIDER,
          HEADER,
          'Stripe-Signature contains more than one timestamp',
        );
      }
      timestampText = item;
    } else if (key === 'v1') {
      const signature = hexToBytes(item, 32);
      if (signature === undefined) {
        throw malformedHeader(
          PROVIDER,
          HEADER,
          'Stripe-Signature v1 value is not 64 hex characters',
        );
      }
      signatures.push(signature);
    }
  }
  if (timestampText === undefined) {
    throw malformedHeader(PROVIDER, HEADER, 'Stripe-Signature has no t= timestamp');
  }
  const timestamp = parseUnixSeconds(timestampText);
  if (timestamp === undefined) {
    throw malformedHeader(PROVIDER, HEADER, 'Stripe-Signature timestamp is not a Unix time');
  }
  if (signatures.length === 0) {
    throw malformedHeader(PROVIDER, HEADER, 'Stripe-Signature has no v1 signature');
  }
  assertSignatureCount(signatures.length, MAX_SIGNATURES_PER_HEADER, PROVIDER, HEADER);
  return { timestampText, timestamp, signatures };
}

/**
 * Verifies a Stripe webhook (`Stripe-Signature` header).
 *
 * Accepts the request if any `v1` signature matches any configured secret and
 * the signed timestamp is within `toleranceSeconds` (default 300) of `now`.
 *
 * @example
 * ```ts
 * const { timestamp } = await verifyStripe({
 *   payload: await request.arrayBuffer(),
 *   headers: request.headers,
 *   secret: env.STRIPE_WEBHOOK_SECRET,
 * });
 * ```
 *
 * @see https://docs.stripe.com/webhooks?verify=verify-manually#verify-manually
 * @throws {@link WebhookVerificationError} when verification fails.
 */
export async function verifyStripe(options: StripeVerifyOptions): Promise<StripeVerifyResult> {
  const window = resolveTolerance(options, DEFAULT_TOLERANCE_SECONDS);
  const { payload, secrets, headers } = readVerifyInput(options, PROVIDER, [HEADER]);
  const header = parseHeader(headers.getRequired(HEADER, 'Stripe-Signature'));

  const message = concatBytes(utf8(`${header.timestampText}.`), payload);
  const valid = await hmacVerifyAny(secrets.map(utf8), message, header.signatures, 'SHA-256');
  if (!valid) {
    throw signatureMismatch(PROVIDER, HEADER, secrets);
  }
  assertFresh(header.timestamp, window, PROVIDER, HEADER);
  return { provider: PROVIDER, timestamp: new Date(header.timestamp * 1000) };
}

/** Options for {@link signStripe}. */
export interface StripeSignOptions extends SignOptions, SignTimestampOptions {}

/**
 * **Test utility.** Produces a `Stripe-Signature` header for `payload`, with
 * one `v1` signature per secret. Use it to exercise your webhook handler in
 * tests; production code only ever verifies.
 *
 * @example
 * ```ts
 * const headers = await signStripe({ payload: body, secret: 'whsec_test' });
 * await app.request('/webhooks/stripe', { method: 'POST', body, headers });
 * ```
 */
export async function signStripe(
  options: StripeSignOptions,
): Promise<SignedHeaders<'stripe-signature'>> {
  const secrets = secretList(options.secret, PROVIDER);
  const timestamp = toUnixSeconds(options.timestamp);
  const message = concatBytes(utf8(`${timestamp}.`), payloadToBytes(options.payload));
  const parts = [`t=${timestamp}`];
  for (const secret of secrets) {
    parts.push(`v1=${bytesToHex(await hmacSign(utf8(secret), message, 'SHA-256'))}`);
  }
  return { [HEADER]: parts.join(',') };
}
