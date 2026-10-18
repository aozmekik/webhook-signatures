import type { ProviderId, VerifyOptions } from '../types.js';
import { payloadToBytes } from './bytes.js';
import type { Bytes } from './bytes.js';
import { assertHeadersInput } from './headers.js';
import { secretList } from './secrets.js';
import type { NonEmptyList } from './secrets.js';

/** The validated inputs that every `verify*` function shares. */
export interface VerifyInput {
  /** A private copy of the raw body. */
  readonly payload: Bytes;
  /** The configured secrets, as given. */
  readonly secrets: NonEmptyList<string>;
}

/**
 * Validates the options every verifier shares, in the documented check order:
 * programmer errors first (`TypeError` for headers or a payload of the wrong
 * type, typically a body parser that already ran), then the secret
 * (`invalid_secret`). Provider-specific options such as the tolerance or the
 * Twilio URL are validated by the caller before this runs.
 *
 * @throws TypeError for headers or a payload of the wrong type.
 * @throws WebhookVerificationError with code `invalid_secret`.
 */
export function readVerifyInput(options: VerifyOptions, provider: ProviderId): VerifyInput {
  assertHeadersInput(options.headers);
  const payload = payloadToBytes(options.payload);
  return { payload, secrets: secretList(options.secret, provider) };
}
