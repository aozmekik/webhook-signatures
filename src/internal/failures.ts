import { WebhookVerificationError } from '../errors.js';
import type { ProviderId } from '../types.js';
import { whitespaceHint } from './secrets.js';

/** Builds a `malformed_header` error. */
export function malformedHeader(
  provider: ProviderId,
  header: string,
  message: string,
): WebhookVerificationError {
  return new WebhookVerificationError('malformed_header', message, { provider, header });
}

/** Builds a `signature_mismatch` error, with a hint about suspicious secrets. */
export function signatureMismatch(
  provider: ProviderId,
  header: string,
  secrets: readonly string[],
  detail = 'No signature matches the payload and the configured secret(s)',
): WebhookVerificationError {
  return new WebhookVerificationError(
    'signature_mismatch',
    `${detail}.${whitespaceHint(secrets)}`,
    { provider, header },
  );
}

/** Throws `malformed_header` when a header lists more signatures than allowed. */
export function assertSignatureCount(
  count: number,
  max: number,
  provider: ProviderId,
  header: string,
): void {
  if (count > max) {
    throw malformedHeader(
      provider,
      header,
      `Header "${header}" lists ${count} signatures; at most ${max} are accepted`,
    );
  }
}
