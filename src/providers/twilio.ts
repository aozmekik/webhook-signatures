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
 * - JSON bodies are not parameters: Twilio adds a `bodySHA256` query parameter
 *   holding the hex SHA-256 of the raw body, signs the URL alone, and the
 *   receiver checks the body against that hash.
 * - Twilio drops URL credentials before signing, and keeps or drops the port
 *   depending on the product, so the URL is tried both with and without its
 *   port (the official SDKs do the same).
 *
 * Twilio signs no timestamp, so there is no replay window; see the README
 * section on replay protection.
 *
 * @module
 */
import { payloadToBytes, utf8 } from '../internal/bytes.js';
import type { Bytes } from '../internal/bytes.js';
import { hmacSign, hmacVerifyAny, sha256 } from '../internal/crypto.js';
import { base64ToBytes, bytesToBase64, bytesToHex } from '../internal/encoding.js';
import { malformedHeader, signatureMismatch } from '../internal/failures.js';
import { requireHeader } from '../internal/headers.js';
import { firstSecret, secretList } from '../internal/secrets.js';
import type { SignOptions, SignedHeaders, VerifyOptions } from '../types.js';

const PROVIDER = 'twilio';
const HEADER = 'x-twilio-signature';
const BODY_HASH_PARAM = 'bodySHA256';

/** Options for {@link verifyTwilio}. `secret` is the account's Auth Token. */
export interface TwilioVerifyOptions extends VerifyOptions {
  /**
   * The exact URL Twilio requested, including scheme, host and query string,
   * as configured in the Twilio console. Behind a proxy, rebuild it from the
   * public host, not from the internal address. Do not decode or re-encode it.
   */
  readonly url: string;
}

/** A verified Twilio request. */
export interface TwilioVerifyResult {
  readonly provider: 'twilio';
  /**
   * `form-params` when the body was signed as sorted form parameters,
   * `body-sha256` when the URL carried a `bodySHA256` hash of a JSON body.
   */
  readonly scheme: 'form-params' | 'body-sha256';
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

function splitUrl(url: string): UrlParts {
  const match = URL_PARTS.exec(url);
  const [, scheme = '', authority = '', rest = ''] = match ?? [];
  if (match === null || !/^https?:\/\/$/i.test(scheme) || authority === '') {
    throw new TypeError('url must be the absolute http(s) URL Twilio requested');
  }
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
function candidateUrls(url: string): readonly string[] {
  const { scheme, host, port, rest } = splitUrl(url);
  const defaultPort = scheme.toLowerCase() === 'https://' ? ':443' : ':80';
  const withoutPort = `${scheme}${host}${rest}`;
  const withPort = `${scheme}${host}${port === '' ? defaultPort : port}${rest}`;
  return [withoutPort, withPort];
}

function bodyHashParam(url: string): string | undefined {
  // Reading the query through URL is safe: only the signed string must stay
  // byte-for-byte, and that is taken from `url` itself.
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (cause) {
    throw new TypeError('url must be the absolute http(s) URL Twilio requested', { cause });
  }
  return parsed.searchParams.get(BODY_HASH_PARAM) ?? undefined;
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
 * Verifies a Twilio request (`X-Twilio-Signature` header).
 *
 * Form-encoded webhooks (most voice and messaging callbacks) are verified over
 * the URL plus the sorted body parameters. If the URL contains a `bodySHA256`
 * query parameter, the body is treated as opaque (JSON) and must hash to it.
 * For GET requests, pass an empty payload.
 *
 * @example
 * ```ts
 * await verifyTwilio({
 *   payload: await request.arrayBuffer(),
 *   headers: request.headers,
 *   secret: env.TWILIO_AUTH_TOKEN,
 *   url: 'https://example.com/twilio/sms', // the URL configured in Twilio
 * });
 * ```
 *
 * @see https://www.twilio.com/docs/usage/security#validating-requests
 * @throws {@link WebhookVerificationError} when verification fails.
 * @throws TypeError when `url` is not an absolute http(s) URL.
 */
export async function verifyTwilio(options: TwilioVerifyOptions): Promise<TwilioVerifyResult> {
  if (typeof options.url !== 'string') {
    throw new TypeError('url must be the absolute http(s) URL Twilio requested');
  }
  const urls = candidateUrls(options.url);
  const expectedBodyHash = bodyHashParam(options.url);
  const secrets = secretList(options.secret, PROVIDER);
  const payload = payloadToBytes(options.payload);
  const signature = base64ToBytes(
    requireHeader(options.headers, HEADER, PROVIDER, 'X-Twilio-Signature'),
    20,
  );
  if (signature === undefined) {
    throw malformedHeader(PROVIDER, HEADER, 'X-Twilio-Signature is not a base64 HMAC-SHA1 digest');
  }

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
    throw signatureMismatch(PROVIDER, HEADER, secrets);
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
    return { provider: PROVIDER, scheme: 'body-sha256' };
  }
  return { provider: PROVIDER, scheme: 'form-params' };
}

/** Options for {@link signTwilio}. Only the first secret (Auth Token) is used. */
export interface TwilioSignOptions extends SignOptions {
  /** The webhook URL being simulated. */
  readonly url: string;
  /**
   * `form-params` (default) signs the body as form parameters. `body-sha256`
   * treats the body as JSON: a `bodySHA256` query parameter is appended to
   * the returned `url`, and only the URL is signed.
   */
  readonly scheme?: 'form-params' | 'body-sha256' | undefined;
}

/** A simulated Twilio request: the URL to call and the headers to send. */
export interface TwilioSignedRequest {
  /** The URL to request. Differs from the input when `bodySHA256` was appended. */
  readonly url: string;
  /** Contains `x-twilio-signature`. */
  readonly headers: SignedHeaders;
}

/**
 * **Test utility.** Signs a simulated Twilio request. Unlike the other
 * `sign*` helpers it returns the URL as well, because for JSON bodies Twilio
 * signs a URL that carries the body hash.
 */
export async function signTwilio(options: TwilioSignOptions): Promise<TwilioSignedRequest> {
  const secret = utf8(firstSecret(options.secret, PROVIDER));
  splitUrl(options.url);
  const payload = payloadToBytes(options.payload);
  let url = options.url;
  let params = '';
  if (options.scheme === 'body-sha256') {
    const hash = bytesToHex(await sha256(payload));
    url += `${url.includes('?') ? '&' : '?'}${BODY_HASH_PARAM}=${hash}`;
  } else {
    params = serializeParams(payload);
  }
  const signature = await hmacSign(secret, utf8(url + params), 'SHA-1');
  return { url, headers: { [HEADER]: bytesToBase64(signature) } };
}
