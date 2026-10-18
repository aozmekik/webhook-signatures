/**
 * Standard Webhooks (symmetric `v1` signatures), as implemented by Svix.
 *
 * Scheme, per https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md
 * and https://docs.svix.com/receiving/verifying-payloads/how-manual :
 *
 * - Headers `webhook-id`, `webhook-timestamp` (Unix seconds) and
 *   `webhook-signature`. Svix sends the same headers with a `svix-` prefix
 *   by default; both spellings are accepted.
 * - `webhook-signature` is a space-delimited list of `<version>,<base64>`
 *   entries. Only `v1` (HMAC-SHA256) entries are checked; others, such as
 *   asymmetric `v1a`, are ignored.
 * - Signed content: `<id>.<timestamp>.<raw body>`.
 * - The secret is base64, conventionally prefixed with `whsec_`; the HMAC key
 *   is the decoded bytes.
 * - The reference libraries reject timestamps more than five minutes away
 *   from now in either direction; the default tolerance is 300 seconds.
 *
 * Resend and Clerk deliver webhooks through Svix, so their webhooks verify
 * with this scheme and the endpoint's `whsec_...` secret.
 *
 * @module
 */
import { concatBytes, payloadToBytes, utf8 } from '../internal/bytes.js';
import type { Bytes } from '../internal/bytes.js';
import { MAX_SIGNATURES_PER_HEADER, hmacSign, hmacVerifyAny } from '../internal/crypto.js';
import { base64ToBytes, bytesToBase64 } from '../internal/encoding.js';
import { assertSignatureCount, malformedHeader, signatureMismatch } from '../internal/failures.js';
import type { CapturedHeaders } from '../internal/headers.js';
import { readVerifyInput } from '../internal/input.js';
import { invalidSecret, secretList } from '../internal/secrets.js';
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

const PROVIDER = 'standard-webhooks';
const SECRET_PREFIX = 'whsec_';
const DEFAULT_TOLERANCE_SECONDS = 300;
const HEADERS = [
  'webhook-id',
  'webhook-timestamp',
  'webhook-signature',
  'svix-id',
  'svix-timestamp',
  'svix-signature',
] as const;

type HeaderName = (typeof HEADERS)[number];

/** Options for {@link verifyStandardWebhook}. `secret` is the endpoint's `whsec_...` secret. */
export interface StandardWebhookVerifyOptions extends VerifyOptions, TimestampToleranceOptions {}

/** A verified Standard Webhooks / Svix message. */
export interface StandardWebhookVerifyResult {
  readonly provider: 'standard-webhooks';
  /**
   * The signed message id (`webhook-id` / `svix-id`). It is identical across
   * retries of the same message, which makes it a sound idempotency key.
   */
  readonly id: string;
  /** The signed `webhook-timestamp` / `svix-timestamp`. */
  readonly timestamp: Date;
}

function decodeSecret(secret: string): Bytes {
  const encoded = secret.startsWith(SECRET_PREFIX) ? secret.slice(SECRET_PREFIX.length) : secret;
  const key = base64ToBytes(encoded);
  if (key === undefined || key.length === 0) {
    throw invalidSecret(PROVIDER, 'Secret must be base64, optionally prefixed with "whsec_"');
  }
  return key;
}

function headerNames(headers: CapturedHeaders<HeaderName>): {
  readonly id: HeaderName;
  readonly timestamp: HeaderName;
  readonly signature: HeaderName;
} {
  const prefix: StandardWebhookHeaderPrefix =
    headers.get('webhook-signature') === undefined && headers.get('svix-signature') !== undefined
      ? 'svix'
      : 'webhook';
  return {
    id: `${prefix}-id`,
    timestamp: `${prefix}-timestamp`,
    signature: `${prefix}-signature`,
  };
}

function parseSignatures(value: string, header: string): readonly Bytes[] {
  const signatures: Bytes[] = [];
  for (const entry of value.split(' ')) {
    if (entry === '') {
      continue;
    }
    const comma = entry.indexOf(',');
    if (comma <= 0) {
      throw malformedHeader(PROVIDER, header, `${header} entries must look like "v1,<base64>"`);
    }
    if (entry.slice(0, comma) !== 'v1') {
      continue;
    }
    const signature = base64ToBytes(entry.slice(comma + 1), 32);
    if (signature === undefined) {
      throw malformedHeader(
        PROVIDER,
        header,
        `${header} v1 value is not a base64 HMAC-SHA256 digest`,
      );
    }
    signatures.push(signature);
  }
  if (signatures.length === 0) {
    throw malformedHeader(PROVIDER, header, `${header} has no v1 signature`);
  }
  assertSignatureCount(signatures.length, MAX_SIGNATURES_PER_HEADER, PROVIDER, header);
  return signatures;
}

/**
 * Verifies a Standard Webhooks message: Svix, and providers that deliver
 * through Svix such as Resend and Clerk.
 *
 * @example
 * ```ts
 * const { id } = await verifyStandardWebhook({
 *   payload: await request.arrayBuffer(),
 *   headers: request.headers, // webhook-* or svix-* headers
 *   secret: env.RESEND_WEBHOOK_SECRET, // "whsec_..."
 * });
 * if (await alreadyProcessed(id)) return new Response(null, { status: 204 });
 * ```
 *
 * @see https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md
 * @throws {@link WebhookVerificationError} when verification fails.
 */
export async function verifyStandardWebhook(
  options: StandardWebhookVerifyOptions,
): Promise<StandardWebhookVerifyResult> {
  const window = resolveTolerance(options, DEFAULT_TOLERANCE_SECONDS);
  const { payload, secrets, headers } = readVerifyInput(options, PROVIDER, HEADERS);
  const keys = secrets.map(decodeSecret);
  const names = headerNames(headers);
  const id = headers.getRequired(names.id, names.id);
  const timestampText = headers.getRequired(names.timestamp, names.timestamp);
  const signatures = parseSignatures(
    headers.getRequired(names.signature, names.signature),
    names.signature,
  );
  const timestamp = parseUnixSeconds(timestampText);
  if (timestamp === undefined) {
    throw malformedHeader(PROVIDER, names.timestamp, `${names.timestamp} is not a Unix time`);
  }

  const message = concatBytes(utf8(`${id}.${timestampText}.`), payload);
  if (!(await hmacVerifyAny(keys, message, signatures, 'SHA-256'))) {
    throw signatureMismatch(PROVIDER, names.signature, []);
  }
  assertFresh(timestamp, window, PROVIDER, names.timestamp);
  return { provider: PROVIDER, id, timestamp: new Date(timestamp * 1000) };
}

/** Header-name prefixes: `webhook` (the Standard Webhooks spec) or `svix`. */
export type StandardWebhookHeaderPrefix = 'webhook' | 'svix';

/** Options for {@link signStandardWebhook}. */
export interface StandardWebhookSignOptions<
  Prefix extends StandardWebhookHeaderPrefix = StandardWebhookHeaderPrefix,
>
  extends SignOptions, SignTimestampOptions {
  /** The message id to sign, for example `msg_2KWPBgLlAfxdpx2AI54pPJ85f4W`. */
  readonly id: string;
  /** Header prefix to emit: `webhook` (the spec, default) or `svix`. */
  readonly headerPrefix?: Prefix | undefined;
}

/** The three headers {@link signStandardWebhook} returns for a given prefix. */
export type StandardWebhookSignedHeaders<Prefix extends StandardWebhookHeaderPrefix> =
  Prefix extends StandardWebhookHeaderPrefix
    ? SignedHeaders<`${Prefix}-id` | `${Prefix}-timestamp` | `${Prefix}-signature`>
    : never;

/**
 * **Test utility.** Produces `webhook-id`, `webhook-timestamp` and
 * `webhook-signature` headers (or their `svix-` equivalents), with one `v1`
 * signature per secret.
 */
export async function signStandardWebhook<Prefix extends StandardWebhookHeaderPrefix = 'webhook'>(
  options: StandardWebhookSignOptions<Prefix>,
): Promise<StandardWebhookSignedHeaders<Prefix>> {
  const keys = secretList(options.secret, PROVIDER).map(decodeSecret);
  if (typeof options.id !== 'string' || options.id === '') {
    throw new TypeError('id must be a non-empty string');
  }
  const timestamp = toUnixSeconds(options.timestamp);
  const prefix = options.headerPrefix ?? 'webhook';
  const message = concatBytes(utf8(`${options.id}.${timestamp}.`), payloadToBytes(options.payload));
  const signatures: string[] = [];
  for (const key of keys) {
    signatures.push(`v1,${bytesToBase64(await hmacSign(key, message, 'SHA-256'))}`);
  }
  // Computed template keys widen to an index signature; the names are exactly
  // the three of `prefix`.
  return {
    [`${prefix}-id`]: options.id,
    [`${prefix}-timestamp`]: String(timestamp),
    [`${prefix}-signature`]: signatures.join(' '),
  } as StandardWebhookSignedHeaders<Prefix>;
}
