import { WebhookVerificationError } from '../errors.js';
import type { HeadersInput, ProviderId } from '../types.js';

interface HeadersLike {
  get(name: string): string | null;
}

function isHeadersLike(value: unknown): value is HeadersLike {
  // Duck-typed so that Headers objects from other realms or polyfills work.
  // A plain header record never has a function-valued property.
  return typeof (value as Partial<HeadersLike> | null)?.get === 'function';
}

/**
 * Reads one header, case-insensitively. Returns `undefined` when the header is
 * absent or blank. Leading and trailing whitespace is removed, as HTTP does.
 *
 * Plain records are scanned for every key that matches ignoring case, so
 * `{ 'Stripe-Signature': v }` and `{ 'stripe-signature': v }` both work. If a
 * record carries several *different* values for the same header (an array, or
 * two differently-cased keys), the request is ambiguous and is rejected with
 * `malformed_header` rather than guessing which value to trust.
 *
 * @param headers - The request headers.
 * @param name - Header name in lower case.
 * @param provider - Used for error reporting.
 */
export function readHeader(
  headers: HeadersInput,
  name: string,
  provider: ProviderId,
): string | undefined {
  if (isHeadersLike(headers)) {
    return normalize(headers.get(name) ?? undefined);
  }
  // Re-checked at runtime for JavaScript callers; the type already excludes it.
  const record: unknown = headers;
  if (typeof record !== 'object' || record === null) {
    throw new TypeError('headers must be a Headers object or a plain object of header values');
  }
  let found: string | undefined;
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== name) {
      continue;
    }
    const value = valueOf(headers[key], name, provider);
    if (value === undefined) {
      continue;
    }
    if (found !== undefined && found !== value) {
      throw duplicate(name, provider);
    }
    found = value;
  }
  return found;
}

/**
 * Like {@link readHeader}, but throws `missing_header` when the header is absent.
 */
export function requireHeader(
  headers: HeadersInput,
  name: string,
  provider: ProviderId,
  displayName: string,
): string {
  const value = readHeader(headers, name, provider);
  if (value === undefined) {
    throw new WebhookVerificationError('missing_header', `Missing ${displayName} header`, {
      provider,
      header: name,
    });
  }
  return value;
}

function valueOf(raw: unknown, name: string, provider: ProviderId): string | undefined {
  if (raw === undefined || raw === null) {
    return undefined;
  }
  if (typeof raw === 'string') {
    return normalize(raw);
  }
  if (Array.isArray(raw)) {
    const values = new Set<string>();
    for (const item of raw as readonly unknown[]) {
      if (typeof item !== 'string') {
        throw new TypeError(`header "${name}" must be a string or an array of strings`);
      }
      const value = normalize(item);
      if (value !== undefined) {
        values.add(value);
      }
    }
    if (values.size > 1) {
      throw duplicate(name, provider);
    }
    const [only] = values;
    return only;
  }
  throw new TypeError(`header "${name}" must be a string or an array of strings`);
}

// HTTP optional whitespace is spaces and horizontal tabs only (RFC 9110, section 5.6.3).
const SURROUNDING_OWS = /^[\t ]+|[\t ]+$/g;

function normalize(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.replace(SURROUNDING_OWS, '');
  return trimmed === '' ? undefined : trimmed;
}

function duplicate(name: string, provider: ProviderId): WebhookVerificationError {
  return new WebhookVerificationError(
    'malformed_header',
    `Header "${name}" was sent more than once with different values`,
    { provider, header: name },
  );
}
