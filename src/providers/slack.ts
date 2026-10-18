/**
 * Slack request signatures (signing secret, version `v0`).
 *
 * Scheme, per https://docs.slack.dev/authentication/verifying-requests-from-slack :
 *
 * - Headers `X-Slack-Request-Timestamp: <unix seconds>` and
 *   `X-Slack-Signature: v0=<hex>`.
 * - Base string: `v0:<timestamp>:<raw body>`.
 * - HMAC-SHA256 keyed with the app's signing secret as UTF-8.
 * - Slack asks receivers to reject timestamps more than five minutes from
 *   local time; the default tolerance is therefore 300 seconds.
 *
 * @module
 */
import { concatBytes, payloadToBytes, utf8 } from '../internal/bytes.js';
import { hmacSign, hmacVerifyAny } from '../internal/crypto.js';
import { bytesToHex, hexToBytes } from '../internal/encoding.js';
import { malformedHeader, signatureMismatch } from '../internal/failures.js';
import { requireHeader } from '../internal/headers.js';
import { readVerifyInput } from '../internal/input.js';
import { firstSecret } from '../internal/secrets.js';
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

const PROVIDER = 'slack';
const SIGNATURE_HEADER = 'x-slack-signature';
const TIMESTAMP_HEADER = 'x-slack-request-timestamp';
const VERSION = 'v0';
const DEFAULT_TOLERANCE_SECONDS = 300;

/** Options for {@link verifySlack}. `secret` is the app's signing secret. */
export interface SlackVerifyOptions extends VerifyOptions, TimestampToleranceOptions {}

/** A verified Slack request. */
export interface SlackVerifyResult {
  readonly provider: 'slack';
  /** The signed `X-Slack-Request-Timestamp`. */
  readonly timestamp: Date;
}

/**
 * Verifies a Slack request (`X-Slack-Signature` and `X-Slack-Request-Timestamp`).
 *
 * Slack signs slash commands and interactivity payloads as
 * `application/x-www-form-urlencoded` and Events API payloads as JSON; in both
 * cases pass the raw body before parsing it.
 *
 * @see https://docs.slack.dev/authentication/verifying-requests-from-slack
 * @throws {@link WebhookVerificationError} when verification fails.
 */
export async function verifySlack(options: SlackVerifyOptions): Promise<SlackVerifyResult> {
  const window = resolveTolerance(options, DEFAULT_TOLERANCE_SECONDS);
  const { payload, secrets } = readVerifyInput(options, PROVIDER);
  const timestampText = requireHeader(
    options.headers,
    TIMESTAMP_HEADER,
    PROVIDER,
    'X-Slack-Request-Timestamp',
  );
  const signatureText = requireHeader(
    options.headers,
    SIGNATURE_HEADER,
    PROVIDER,
    'X-Slack-Signature',
  );

  const timestamp = parseUnixSeconds(timestampText);
  if (timestamp === undefined) {
    throw malformedHeader(
      PROVIDER,
      TIMESTAMP_HEADER,
      'X-Slack-Request-Timestamp is not a Unix time',
    );
  }
  const prefix = `${VERSION}=`;
  const signature = signatureText.startsWith(prefix)
    ? hexToBytes(signatureText.slice(prefix.length), 32)
    : undefined;
  if (signature === undefined) {
    throw malformedHeader(
      PROVIDER,
      SIGNATURE_HEADER,
      'X-Slack-Signature must be "v0=" followed by 64 hex characters',
    );
  }

  const message = concatBytes(utf8(`${VERSION}:${timestampText}:`), payload);
  if (!(await hmacVerifyAny(secrets.map(utf8), message, [signature], 'SHA-256'))) {
    throw signatureMismatch(PROVIDER, SIGNATURE_HEADER, secrets);
  }
  assertFresh(timestamp, window, PROVIDER, TIMESTAMP_HEADER);
  return { provider: PROVIDER, timestamp: new Date(timestamp * 1000) };
}

/** Options for {@link signSlack}. Only the first secret is used. */
export interface SlackSignOptions extends SignOptions, SignTimestampOptions {}

/**
 * **Test utility.** Produces `X-Slack-Request-Timestamp` and
 * `X-Slack-Signature` headers for `payload`.
 */
export async function signSlack(
  options: SlackSignOptions,
): Promise<SignedHeaders<'x-slack-request-timestamp' | 'x-slack-signature'>> {
  const secret = utf8(firstSecret(options.secret, PROVIDER));
  const timestamp = toUnixSeconds(options.timestamp);
  const message = concatBytes(utf8(`${VERSION}:${timestamp}:`), payloadToBytes(options.payload));
  const signature = bytesToHex(await hmacSign(secret, message, 'SHA-256'));
  return {
    [TIMESTAMP_HEADER]: String(timestamp),
    [SIGNATURE_HEADER]: `${VERSION}=${signature}`,
  };
}
