/**
 * GitHub webhook signatures.
 *
 * Scheme, per https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries :
 *
 * - Header `X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of the raw body>`,
 *   keyed with the webhook secret as UTF-8.
 * - The legacy SHA-1 `X-Hub-Signature` header is not accepted.
 * - GitHub signs no timestamp, so there is no replay window; see the README
 *   section on replay protection.
 *
 * @module
 */
import { payloadToBytes, utf8 } from '../internal/bytes.js';
import { hmacSign, hmacVerifyAny } from '../internal/crypto.js';
import { bytesToHex, hexToBytes } from '../internal/encoding.js';
import { malformedHeader, signatureMismatch } from '../internal/failures.js';
import { readVerifyInput } from '../internal/input.js';
import { firstSecret } from '../internal/secrets.js';
import { WebhookVerificationError } from '../errors.js';
import type { SignOptions, SignedHeaders, VerifyOptions } from '../types.js';

const PROVIDER = 'github';
const HEADER = 'x-hub-signature-256';
const LEGACY_HEADER = 'x-hub-signature';
const DELIVERY_HEADER = 'x-github-delivery';
const EVENT_HEADER = 'x-github-event';
const HEADERS = [HEADER, LEGACY_HEADER, DELIVERY_HEADER, EVENT_HEADER] as const;
const PREFIX = 'sha256=';

/** Options for {@link verifyGitHub}. `secret` is the webhook's secret token. */
export type GitHubVerifyOptions = VerifyOptions;

/** A verified GitHub webhook. */
export interface GitHubVerifyResult {
  readonly provider: 'github';
  /**
   * `X-GitHub-Delivery` (a GUID), if present. Not covered by the signature:
   * use it to drop GitHub's own redeliveries, not as a security control.
   * @see https://docs.github.com/en/webhooks/webhook-events-and-payloads#delivery-headers
   */
  readonly deliveryId: string | undefined;
  /** `X-GitHub-Event` (for example `push`), if present. Not covered by the signature. */
  readonly event: string | undefined;
}

/**
 * Verifies a GitHub webhook (`X-Hub-Signature-256` header).
 *
 * @example
 * ```ts
 * const { event } = await verifyGitHub({
 *   payload: await request.arrayBuffer(),
 *   headers: request.headers,
 *   secret: env.GITHUB_WEBHOOK_SECRET,
 * });
 * ```
 *
 * @see https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
 * @throws {@link WebhookVerificationError} when verification fails.
 */
export async function verifyGitHub(options: GitHubVerifyOptions): Promise<GitHubVerifyResult> {
  const { payload, secrets, headers } = readVerifyInput(options, PROVIDER, HEADERS);
  const value = headers.get(HEADER);
  if (value === undefined) {
    const legacyOnly = headers.get(LEGACY_HEADER) !== undefined;
    throw new WebhookVerificationError(
      'missing_header',
      legacyOnly
        ? 'Missing X-Hub-Signature-256 header (only the legacy SHA-1 X-Hub-Signature was sent, which is not accepted)'
        : 'Missing X-Hub-Signature-256 header (is a secret configured for this webhook?)',
      { provider: PROVIDER, header: HEADER },
    );
  }
  const signature = value.startsWith(PREFIX)
    ? hexToBytes(value.slice(PREFIX.length), 32)
    : undefined;
  if (signature === undefined) {
    throw malformedHeader(
      PROVIDER,
      HEADER,
      'X-Hub-Signature-256 must be "sha256=" followed by 64 hex characters',
    );
  }
  if (!(await hmacVerifyAny(secrets.map(utf8), payload, [signature], 'SHA-256'))) {
    throw signatureMismatch(PROVIDER, HEADER, secrets);
  }
  return {
    provider: PROVIDER,
    deliveryId: headers.get(DELIVERY_HEADER),
    event: headers.get(EVENT_HEADER),
  };
}

/** Options for {@link signGitHub}. Only the first secret is used. */
export type GitHubSignOptions = SignOptions;

/**
 * **Test utility.** Produces an `X-Hub-Signature-256` header for `payload`.
 * GitHub sends a single signature, so when a list of secrets is given only the
 * first one is used.
 */
export async function signGitHub(
  options: GitHubSignOptions,
): Promise<SignedHeaders<'x-hub-signature-256'>> {
  const secret = utf8(firstSecret(options.secret, PROVIDER));
  const signature = await hmacSign(secret, payloadToBytes(options.payload), 'SHA-256');
  return { [HEADER]: `${PREFIX}${bytesToHex(signature)}` };
}
