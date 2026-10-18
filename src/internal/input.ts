import type { ProviderId, VerifyOptions } from '../types.js';
import { payloadToBytes } from './bytes.js';
import type { Bytes } from './bytes.js';
import { captureHeaders } from './headers.js';
import type { CapturedHeaders } from './headers.js';
import { secretList } from './secrets.js';
import type { NonEmptyList } from './secrets.js';

/** The validated inputs that every `verify*` function shares. */
export interface VerifyInput<HeaderName extends string> {
  /** A private copy of the raw body. */
  readonly payload: Bytes;
  /** The configured secrets, as given. */
  readonly secrets: NonEmptyList<string>;
  /** The headers the verifier reads, already type-checked. */
  readonly headers: CapturedHeaders<HeaderName>;
}

/**
 * Validates the options every verifier shares, in the documented check order:
 * programmer errors first (`TypeError` for headers or header values of the
 * wrong type, or for a payload that is not raw bytes, typically because a
 * body parser already ran), then the secret (`invalid_secret`).
 * Provider-specific options such as the tolerance or the Twilio URL are
 * validated by the caller before this runs.
 *
 * @param headerNames - Every header the verifier reads, in lower case. Only
 *   these are type-checked, and only these can be read from the result.
 * @throws TypeError for headers, header values or a payload of the wrong type.
 * @throws WebhookVerificationError with code `invalid_secret`.
 */
export function readVerifyInput<const HeaderName extends string>(
  options: VerifyOptions,
  provider: ProviderId,
  headerNames: readonly HeaderName[],
): VerifyInput<HeaderName> {
  const headers = captureHeaders(options.headers, headerNames, provider);
  const payload = payloadToBytes(options.payload);
  return { payload, secrets: secretList(options.secret, provider), headers };
}
