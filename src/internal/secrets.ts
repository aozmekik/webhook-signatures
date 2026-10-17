import { WebhookVerificationError } from '../errors.js';
import type { ProviderId } from '../types.js';

/** A read-only list with at least one element. */
export type NonEmptyList<T> = readonly [T, ...T[]];

/**
 * Validates the `secret` option and returns it as a non-empty list.
 *
 * Secrets are used exactly as given: no trimming, because some providers
 * (GitHub, Lemon Squeezy) let users choose secrets that may contain spaces.
 *
 * @throws WebhookVerificationError with code `invalid_secret`.
 */
export function secretList(secret: unknown, provider: ProviderId): NonEmptyList<string> {
  const list: readonly unknown[] = Array.isArray(secret) ? secret : [secret];
  if (list.length === 0) {
    throw invalidSecret(provider, 'No secret was provided (empty list)');
  }
  for (const item of list) {
    if (typeof item !== 'string' || item === '') {
      throw invalidSecret(
        provider,
        `Secret must be a non-empty string, but received ${item === '' ? 'an empty string' : typeof item}`,
      );
    }
  }
  return list as NonEmptyList<string>;
}

/** Builds an `invalid_secret` error. */
export function invalidSecret(provider: ProviderId, message: string): WebhookVerificationError {
  return new WebhookVerificationError('invalid_secret', message, { provider });
}

/**
 * Appended to `signature_mismatch` messages when a secret has leading or
 * trailing whitespace: usually a stray newline from an environment file.
 * Mentions the shape of the secret only, never its content.
 */
export function whitespaceHint(secrets: readonly string[]): string {
  return secrets.some((s) => s.trim() !== s)
    ? ' Note: a configured secret has leading or trailing whitespace; check how it is loaded.'
    : '';
}

/**
 * For signing helpers of schemes that carry a single signature: validates the
 * `secret` option and returns its first entry.
 */
export function firstSecret(secret: unknown, provider: ProviderId): string {
  return secretList(secret, provider)[0];
}
