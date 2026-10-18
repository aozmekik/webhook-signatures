/**
 * Twilio request signatures (`X-Twilio-Signature`).
 *
 * Scheme, per https://www.twilio.com/docs/usage/security#validating-requests
 * and https://www.twilio.com/docs/usage/webhooks/webhooks-security :
 *
 * - String to sign: the full URL Twilio requested (scheme through query
 *   string), followed, for `application/x-www-form-urlencoded` POSTs, by every
 *   POST parameter as `name + value` with no delimiters, sorted by name
 *   (case-sensitive, Unix-style ordering).
 * - HMAC-SHA1 keyed with the account's Auth Token, base64-encoded.
 * - JSON bodies are not parameters: Twilio appends a `bodySHA256` query
 *   parameter holding the hex SHA-256 of the raw body to the webhook URL,
 *   signs the URL alone, and the receiver checks the body against that hash.
 * - Twilio drops URL credentials before signing, and keeps or drops the port
 *   depending on the product, so the URL is tried both with and without its
 *   port (the official SDKs do the same).
 *
 * Because names and values are concatenated without delimiters, a signature
 * authenticates only the concatenated string, not one particular split of it
 * into parameters. For the same reason the scheme is configured per endpoint
 * rather than inferred from the URL (see {@link TwilioVerifyOptions.scheme}).
 * Twilio signs no timestamp either, so there is no replay window. The README
 * section on Twilio lists what handlers should do about both.
 *
 * @module
 */
import { payloadToBytes, utf8 } from '../internal/bytes.js';
import type { Bytes } from '../internal/bytes.js';
import { hmacSign, hmacVerifyAny, sha256 } from '../internal/crypto.js';
import { base64ToBytes, bytesToBase64, bytesToHex } from '../internal/encoding.js';
import { malformedHeader, signatureMismatch } from '../internal/failures.js';
import { readVerifyInput } from '../internal/input.js';
import { firstSecret } from '../internal/secrets.js';
import type { SignOptions, SignedHeaders, VerifyOptions } from '../types.js';

const PROVIDER = 'twilio';
const HEADER = 'x-twilio-signature';
const BODY_HASH_PARAM = 'bodySHA256';
const INVALID_URL = 'url must be the absolute http(s) URL Twilio requested';

/**
 * How a Twilio request's body is covered by its signature:
 *
 * - `form-params`: form-encoded POST parameters are appended to the URL and
 *   signed with it (most voice and messaging callbacks). GET callbacks, whose
 *   parameters are all in the query string, use this scheme with an empty body.
 * - `body-sha256`: JSON bodies. Twilio appends `bodySHA256=<hex SHA-256 of the
 *   body>` to the URL and signs the URL alone.
 */
export type TwilioScheme = 'form-params' | 'body-sha256';

/** Options for {@link verifyTwilio}. `secret` is the account's Auth Token. */
export interface TwilioVerifyOptions extends VerifyOptions {
  /**
   * The full URL Twilio requested: the public scheme and host, then the
   * incoming request's path and query string exactly as received. It includes
   * every query parameter Twilio appended: `bodySHA256` for JSON bodies, and
   * all parameters of a GET callback. Behind a proxy, use the public origin
   * rather than the internal address, and do not decode or re-encode the path
   * or query.
   *
   * For form-encoded POST callbacks Twilio appends nothing, so this is the
   * webhook URL configured in Twilio and a constant works.
   *
   * @example
   * ```ts
   * const { pathname, search } = new URL(request.url);
   * const url = `https://example.com${pathname}${search}`; // the public origin
   * ```
   */
  readonly url: string;
  /**
   * The scheme this endpoint receives; defaults to `form-params`. Pass
   * `body-sha256` for endpoints that receive JSON.
   *
   * The scheme is deliberately not inferred from the URL. Since Twilio
   * concatenates parameters without delimiters, a captured form-params
   * signature can be presented again with a URL that carries a
   * `bodySHA256` the attacker chose, so a verifier that switched to JSON mode
   * on seeing `bodySHA256` would accept an attacker-chosen JSON body. Keep
   * JSON and form callbacks on separate endpoints, each configured for its
   * scheme.
   */
  readonly scheme?: TwilioScheme | undefined;
}

/** A verified Twilio request. */
export interface TwilioVerifyResult {
  readonly provider: 'twilio';
  /** The scheme the request was verified with, as configured. */
  readonly scheme: TwilioScheme;
}

interface UrlParts {
  readonly scheme: string;
  readonly host: string;
  readonly port: string;
  readonly rest: string;
}

// Splits an absolute URL without normalizing it: Twilio signs the URL string
// exactly as configured, so it must not be re-serialized through `URL`.
const URL_PARTS = /^([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^/?#]*)(.*)$/s;

function splitUrl(url: unknown): UrlParts {
  if (typeof url !== 'string') {
    throw new TypeError(INVALID_URL);
  }
  const match = URL_PARTS.exec(url);
  const [, scheme = '', authority = '', rest = ''] = match ?? [];
  if (match === null || !/^https?:\/\/$/i.test(scheme) || authority === '') {
    throw new TypeError(INVALID_URL);
  }
  // Also reject what the WHATWG parser rejects (spaces in the host, ...).
  try {
    new URL(url);
  } catch (cause) {
    throw new TypeError(INVALID_URL, { cause });
  }
  // Credentials (`user:password@`) are dropped, as Twilio does before signing.
  const hostAndPort = authority.slice(authority.lastIndexOf('@') + 1);
  const portStart = hostAndPort.indexOf(':', hostAndPort.lastIndexOf(']') + 1);
  return {
    scheme,
    host: portStart === -1 ? hostAndPort : hostAndPort.slice(0, portStart),
    port: portStart === -1 ? '' : hostAndPort.slice(portStart),
    rest,
  };
}

/** The URL as Twilio may have signed it: credentials removed, with and without the port. */
function candidateUrls({ scheme, host, port, rest }: UrlParts): readonly string[] {
  const defaultPort = scheme.toLowerCase() === 'https://' ? ':443' : ':80';
  const withoutPort = `${scheme}${host}${rest}`;
  const withPort = `${scheme}${host}${port === '' ? defaultPort : port}${rest}`;
  return [withoutPort, withPort];
}

function resolveScheme(scheme: unknown): TwilioScheme {
  if (scheme === undefined || scheme === 'form-params' || scheme === 'body-sha256') {
    return scheme ?? 'form-params';
  }
  throw new TypeError('scheme must be "form-params" or "body-sha256"');
}

/**
 * Concatenates form parameters the way Twilio signs them: sorted by name
 * (UTF-16 code unit order, which is byte order for the ASCII names Twilio
 * uses), `name + value` for each. Twilio's docs do not cover repeated names;
 * like the official Node.js helper library, their distinct values are sorted
 * and each is appended as `name + value`.
 */
function serializeParams(body: Bytes): string {
  const grouped = new Map<string, Set<string>>();
  for (const [name, value] of new URLSearchParams(new TextDecoder().decode(body))) {
    const values = grouped.get(name);
    if (values === undefined) {
      grouped.set(name, new Set([value]));
    } else {
      values.add(value);
    }
  }
  // Map keys are unique, so the comparator never needs to return 0.
  const sorted = [...grouped].sort(([a], [b]) => (a < b ? -1 : 1));
  let out = '';
  for (const [name, values] of sorted) {
    for (const value of [...values].sort()) {
      out += name + value;
    }
  }
  return out;
}

/**
 * Returns the signed body hash of a JSON request. Twilio appends `bodySHA256`
 * to the webhook URL, so a genuine URL ends with exactly one such parameter
 * and has no fragment. Requiring that shape (rather than reading the
 * parameter from anywhere in the query) rejects URLs re-assembled from a
 * form-params signature, whose signed string continues with further
 * parameters after any `bodySHA256` an attacker planted in a value.
 */
function signedBodyHash(url: string, secrets: readonly string[]): string {
  const query = new URL(url).searchParams;
  const last = [...query].at(-1);
  if (
    url.includes('#') ||
    last?.[0] !== BODY_HASH_PARAM ||
    query.getAll(BODY_HASH_PARAM).length !== 1
  ) {
    throw signatureMismatch(
      PROVIDER,
      HEADER,
      secrets,
      'For scheme "body-sha256" the URL must end with the single bodySHA256 query parameter Twilio appends to JSON requests',
    );
  }
  return last[1];
}

/**
 * Verifies a Twilio request (`X-Twilio-Signature` header).
 *
 * With the default `scheme: 'form-params'`, the signature covers the URL plus
 * the sorted form parameters of the body (pass an empty payload for GET
 * callbacks). With `scheme: 'body-sha256'`, it covers the URL, whose
 * `bodySHA256` parameter must match the SHA-256 of the raw body.
 *
 * A verified form body proves only the concatenated `name + value` string:
 * read parameters with `URLSearchParams.get()`, reject unexpected or repeated
 * names, and make the handler idempotent (on `MessageSid` / `CallSid`).
 *
 * @example
 * ```ts
 * await verifyTwilio({
 *   payload: await request.arrayBuffer(),
 *   headers: request.headers,
 *   secret: env.TWILIO_AUTH_TOKEN,
 *   url: 'https://example.com/twilio/sms', // form POSTs: the configured webhook URL
 * });
 * ```
 *
 * @see https://www.twilio.com/docs/usage/security#validating-requests
 * @throws {@link WebhookVerificationError} when verification fails.
 * @throws TypeError when `url` is not an absolute http(s) URL or `scheme` is unknown.
 */
export async function verifyTwilio(options: TwilioVerifyOptions): Promise<TwilioVerifyResult> {
  const scheme = resolveScheme(options.scheme);
  const urls = candidateUrls(splitUrl(options.url));
  const { payload, secrets, headers } = readVerifyInput(options, PROVIDER, [HEADER]);
  const signature = base64ToBytes(headers.getRequired(HEADER, 'X-Twilio-Signature'), 20);
  if (signature === undefined) {
    throw malformedHeader(PROVIDER, HEADER, 'X-Twilio-Signature is not a base64 HMAC-SHA1 digest');
  }
  const expectedBodyHash =
    scheme === 'body-sha256' ? signedBodyHash(options.url, secrets) : undefined;

  const params = expectedBodyHash === undefined ? serializeParams(payload) : '';
  const keys = secrets.map(utf8);
  let valid = false;
  for (const url of urls) {
    if (await hmacVerifyAny(keys, utf8(url + params), [signature], 'SHA-1')) {
      valid = true;
      break;
    }
  }
  if (!valid) {
    throw signatureMismatch(
      PROVIDER,
      HEADER,
      secrets,
      scheme === 'form-params' && new URL(options.url).searchParams.has(BODY_HASH_PARAM)
        ? 'No signature matches. The URL carries bodySHA256: if this endpoint receives JSON, pass scheme "body-sha256"'
        : undefined,
    );
  }
  if (expectedBodyHash !== undefined) {
    // The URL, and therefore the hash, is authentic at this point; the body
    // hash is public information, so a plain comparison is fine.
    if (bytesToHex(await sha256(payload)) !== expectedBodyHash.toLowerCase()) {
      throw signatureMismatch(
        PROVIDER,
        HEADER,
        secrets,
        'The body does not match the signed bodySHA256 hash',
      );
    }
  }
  return { provider: PROVIDER, scheme };
}

/** Options for {@link signTwilio}. Only the first secret (Auth Token) is used. */
export interface TwilioSignOptions extends SignOptions {
  /** The webhook URL being simulated, as configured in Twilio. */
  readonly url: string;
  /**
   * `form-params` (default) signs the body as form parameters. `body-sha256`
   * treats the body as JSON: a `bodySHA256` query parameter is appended to
   * the returned `url`, and only the URL is signed.
   */
  readonly scheme?: TwilioScheme | undefined;
}

/** A simulated Twilio request: the URL to call and the headers to send. */
export interface TwilioSignedRequest {
  /** The URL to request. Differs from the input when `bodySHA256` was appended. */
  readonly url: string;
  /** The `x-twilio-signature` header. */
  readonly headers: SignedHeaders<'x-twilio-signature'>;
}

/**
 * **Test utility.** Signs a simulated Twilio request. Unlike the other
 * `sign*` helpers it returns the URL as well, because for JSON bodies Twilio
 * signs a URL that carries the body hash.
 *
 * As Twilio does, the signature is computed over the URL without any
 * `user:password@` credentials; the returned `url` keeps them.
 *
 * @throws TypeError when `url` is not an absolute http(s) URL, or carries a
 *   `#fragment` with `scheme: 'body-sha256'` (Twilio appends the hash to the
 *   query, and request URLs carry no fragment).
 */
export async function signTwilio(options: TwilioSignOptions): Promise<TwilioSignedRequest> {
  const secret = utf8(firstSecret(options.secret, PROVIDER));
  const scheme = resolveScheme(options.scheme);
  splitUrl(options.url);
  const payload = payloadToBytes(options.payload);
  let url = options.url;
  let params = '';
  if (scheme === 'body-sha256') {
    if (url.includes('#')) {
      throw new TypeError(
        'url must not contain a #fragment when signing a JSON (body-sha256) request',
      );
    }
    const hash = bytesToHex(await sha256(payload));
    url += `${url.includes('?') ? '&' : '?'}${BODY_HASH_PARAM}=${hash}`;
  } else {
    params = serializeParams(payload);
  }
  const { scheme: prefix, host, port, rest } = splitUrl(url);
  const signature = await hmacSign(
    secret,
    utf8(`${prefix}${host}${port}${rest}${params}`),
    'SHA-1',
  );
  return { url, headers: { [HEADER]: bytesToBase64(signature) } };
}
