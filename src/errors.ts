import type { ProviderId } from './types.js';

/**
 * Stable, machine-readable reasons a webhook failed verification.
 *
 * - `missing_header`: a required header is absent or empty.
 * - `malformed_header`: a header is present but does not follow the
 *   provider's documented format (bad encoding, wrong length, no supported
 *   signature scheme, duplicated values, ...).
 * - `timestamp_out_of_tolerance`: the signature is valid, but the signed
 *   timestamp is too old or too far in the future (possible replay or clock skew).
 * - `signature_mismatch`: no supplied signature matches any configured secret.
 *   The body may have been altered, or the secret is wrong.
 * - `invalid_secret`: the configured secret is unusable (empty, not a string,
 *   or not valid base64 for Standard Webhooks). This is a configuration error.
 */
export type WebhookVerificationErrorCode =
  | 'missing_header'
  | 'malformed_header'
  | 'timestamp_out_of_tolerance'
  | 'signature_mismatch'
  | 'invalid_secret';

/** Extra context attached to a {@link WebhookVerificationError}. */
export interface WebhookVerificationErrorOptions {
  /** The scheme that was being verified. */
  readonly provider: ProviderId;
  /** The (lower-case) header the error is about, when there is one. */
  readonly header?: string | undefined;
  /** The underlying error, when there is one. */
  readonly cause?: unknown;
}

/**
 * Thrown when a webhook request cannot be verified.
 *
 * Branch on {@link WebhookVerificationError.code} rather than on the message;
 * codes are part of the public API, messages are not. Messages never contain
 * secrets or expected signatures, so they are safe to log.
 *
 * Programmer errors (a payload that is not a string or bytes, a negative
 * tolerance, a Twilio URL that is not absolute) are reported with a plain
 * `TypeError` or `RangeError` instead.
 */
export class WebhookVerificationError extends Error {
  /** Always `"WebhookVerificationError"`. */
  override readonly name = 'WebhookVerificationError' as const;
  /** Why verification failed. */
  readonly code: WebhookVerificationErrorCode;
  /** The scheme that was being verified. */
  readonly provider: ProviderId;
  /** The (lower-case) header the error is about, when there is one. */
  readonly header: string | undefined;

  /**
   * @param code - Why verification failed.
   * @param message - Human-readable detail, safe to log.
   * @param options - Provider, header and optional cause.
   */
  constructor(
    code: WebhookVerificationErrorCode,
    message: string,
    options: WebhookVerificationErrorOptions,
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.code = code;
    this.provider = options.provider;
    this.header = options.header;
  }
}
