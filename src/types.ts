/**
 * Identifiers of the supported webhook signature schemes, as accepted by
 * {@link verifyWebhook}.
 */
export type ProviderId =
  | 'stripe'
  | 'github'
  | 'slack'
  | 'shopify'
  | 'standard-webhooks'
  | 'twilio'
  | 'paddle'
  | 'lemon-squeezy';

/**
 * The raw request body, byte-for-byte as it was received.
 *
 * Signatures are computed over the exact bytes the provider sent, so this must
 * be read before any JSON or form parser touches the request. Strings are
 * encoded as UTF-8; prefer bytes (`Uint8Array` / `ArrayBuffer`) when your
 * framework offers them. Node.js `Buffer` is a `Uint8Array` and works as is.
 */
export type WebhookPayload = string | Uint8Array | ArrayBuffer;

/**
 * Request headers: either a Fetch API `Headers` object or a plain record such
 * as Node.js `IncomingHttpHeaders`. Header names are matched case-insensitively.
 */
export type HeadersInput =
  Headers | Readonly<Record<string, string | readonly string[] | undefined>>;

/**
 * A signing secret, or a list of secrets that are all accepted. Pass a list
 * while rotating secrets: verification succeeds if any secret matches.
 */
export type SecretInput = string | readonly string[];

/** Options shared by every `verify*` function. */
export interface VerifyOptions {
  /** The raw request body. See {@link WebhookPayload}. */
  readonly payload: WebhookPayload;
  /** The request headers. See {@link HeadersInput}. */
  readonly headers: HeadersInput;
  /** The signing secret (or secrets, during rotation). See {@link SecretInput}. */
  readonly secret: SecretInput;
}

/**
 * Replay-window options for schemes that sign a timestamp.
 *
 * A signed timestamp too far in the past, or too far in the future, is
 * rejected with `timestamp_out_of_tolerance`. Rejecting future timestamps
 * bounds how long a request stays replayable when the provider's clock runs
 * ahead of yours.
 */
export interface TimestampToleranceOptions {
  /**
   * Maximum allowed difference, in seconds, between the signed timestamp and
   * `now`, in either direction. Defaults to the provider's documented value.
   * `Infinity` disables the check; this is never recommended outside tests.
   * Paddle, whose default is only 5 seconds, allows at least 60 seconds in the
   * future direction; see {@link verifyPaddle}.
   */
  readonly toleranceSeconds?: number | undefined;
  /** Clock used for the tolerance check. Defaults to `new Date()`. */
  readonly now?: Date | undefined;
}

/** Options shared by every `sign*` test helper. */
export interface SignOptions {
  /** The body to sign. */
  readonly payload: WebhookPayload;
  /**
   * The secret to sign with. For schemes that carry several signatures in one
   * header (Stripe, Standard Webhooks, Paddle) a list produces one signature
   * per secret, which is how those providers behave during secret rotation.
   */
  readonly secret: SecretInput;
}

/** Signing-time options for schemes that sign a timestamp. */
export interface SignTimestampOptions {
  /** Timestamp to embed in the signature. Defaults to `new Date()`. */
  readonly timestamp?: Date | undefined;
}

/** Header names (lower-case) mapped to values, as produced by the `sign*` helpers. */
export type SignedHeaders = Record<string, string>;
