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
 * Throws a `TypeError` unless `headers` is a `Headers`-like object or a plain
 * record. Re-checked at runtime for JavaScript callers; the type already
 * excludes the rest.
 *
 * A `Map` is rejected explicitly: it has a `get` method, so it would pass for
 * a `Headers` object, but its lookups are case-sensitive and the usual
 * `X-Hub-Signature-256` spelling would then look like a missing header.
 */
function assertHeadersInput(headers: unknown): asserts headers is HeadersInput {
  if (typeof headers !== 'object' || headers === null) {
    throw new TypeError('headers must be a Headers object or a plain object of header values');
  }
  if (Object.prototype.toString.call(headers) === '[object Map]') {
    throw new TypeError(
      'headers must be a Headers object or a plain object of header values, not a Map; ' +
        'convert it with Object.fromEntries(map) or new Headers([...map])',
    );
  }
}

/**
 * The headers one verifier reads, captured by {@link captureHeaders}.
 *
 * `Name` is the union of the names the capture was made with, so a verifier
 * cannot read a header whose value was not type-checked before the secret.
 */
export interface CapturedHeaders<Name extends string> {
  /**
   * Returns the header's value without surrounding whitespace, or `undefined`
   * when it is absent or blank.
   *
   * @throws WebhookVerificationError with code `malformed_header` when the
   *   header was sent more than once with different values.
   */
  get(name: Name): string | undefined;
  /**
   * Like {@link CapturedHeaders.get}, but throws `missing_header` when the
   * header is absent or blank.
   *
   * @param displayName - The header's usual spelling, for the error message.
   */
  getRequired(name: Name, displayName: string): string;
}

/**
 * Reads the named headers once, case-insensitively, and type-checks them.
 *
 * This is the only place where header *types* are checked, so that every
 * programmer error in `headers` surfaces as a `TypeError` before the secret is
 * looked at: `headers` that is not an object, a `Map`, or a value of one of
 * the named headers that is not a string or an array of strings. Values of
 * other headers are never inspected. Verification failures about the
 * headers' *content* (`missing_header`, `malformed_header`) are raised by the
 * lookups instead, which run after the secret check, in the documented order.
 *
 * Leading and trailing whitespace is removed, as HTTP does. Plain records are
 * scanned for every key that matches ignoring case, so
 * `{ 'Stripe-Signature': v }` and `{ 'stripe-signature': v }` both work. If a
 * record carries several *different* values for the same header (an array, or
 * two differently-cased keys), the request is ambiguous: looking the header up
 * throws `malformed_header` rather than guessing which value to trust.
 *
 * @param headers - The request headers, as the caller passed them.
 * @param names - Every header the verifier may read, in lower case.
 * @param provider - Used for error reporting.
 * @throws TypeError for headers or header values of the wrong type.
 */
export function captureHeaders<const Name extends string>(
  headers: unknown,
  names: readonly Name[],
  provider: ProviderId,
): CapturedHeaders<Name> {
  assertHeadersInput(headers);
  // Every key is one of `names`, so the lookups below always find their entry.
  const captured = Object.fromEntries(
    names.map((name) => [name, distinctValues(headers, name)]),
  ) as Record<Name, readonly string[]>;

  const get = (name: Name): string | undefined => {
    const values = captured[name];
    if (values.length > 1) {
      throw new WebhookVerificationError(
        'malformed_header',
        `Header "${name}" was sent more than once with different values`,
        { provider, header: name },
      );
    }
    return values[0];
  };
  return {
    get,
    getRequired(name, displayName) {
      const value = get(name);
      if (value === undefined) {
        throw new WebhookVerificationError('missing_header', `Missing ${displayName} header`, {
          provider,
          header: name,
        });
      }
      return value;
    },
  };
}

/** The distinct non-blank values of header `name`, trimmed. */
function distinctValues(headers: HeadersInput, name: string): readonly string[] {
  const values = new Set<string>();
  if (isHeadersLike(headers)) {
    addValues(values, headers.get(name), name);
  } else {
    for (const key of Object.keys(headers)) {
      if (key.toLowerCase() === name) {
        addValues(values, headers[key], name);
      }
    }
  }
  return [...values];
}

/**
 * Adds one raw header value (a string or an array of strings) to `values`.
 * `undefined` and `null`, which some frameworks produce, mean "absent".
 */
function addValues(values: Set<string>, raw: unknown, name: string): void {
  if (raw === undefined || raw === null) {
    return;
  }
  const items: readonly unknown[] = Array.isArray(raw) ? raw : [raw];
  for (const item of items) {
    if (typeof item !== 'string') {
      throw new TypeError(`header "${name}" must be a string or an array of strings`);
    }
    const value = trimOws(item);
    if (value !== '') {
      values.add(value);
    }
  }
}

// HTTP optional whitespace is spaces and horizontal tabs only (RFC 9110, section 5.6.3).
function isOws(charCode: number): boolean {
  return charCode === 0x20 || charCode === 0x09;
}

/**
 * Trims optional whitespace with two index scans. Header values arrive before
 * any authentication, so this must stay linear in the value's length: a
 * regular expression such as `/^[\t ]+|[\t ]+$/g` backtracks quadratically
 * on long interior runs of whitespace.
 */
function trimOws(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && isOws(value.charCodeAt(start))) {
    start++;
  }
  while (end > start && isOws(value.charCodeAt(end - 1))) {
    end--;
  }
  return value.slice(start, end);
}
