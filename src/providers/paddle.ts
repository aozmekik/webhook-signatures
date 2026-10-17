/**
 * Paddle Billing webhook signatures.
 *
 * Scheme, per https://developer.paddle.com/webhooks/signature-verification :
 *
 * - Header `Paddle-Signature: ts=<unix seconds>;h1=<hex>`. During a secret
 *   rotation Paddle sends more than one `h1`; any of them may match.
 * - Signed payload: `<ts>:<raw body>`.
 * - HMAC-SHA256 keyed with the notification destination's secret key
 *   (`pdl_ntfset_...`), used verbatim.
 * - Paddle's SDKs reject events whose timestamp is more than **5 seconds**
 *   old, and the docs use the same value. This library follows that default;
 *   raise `toleranceSeconds` if your clock or queueing needs more room.
 *
 * Paddle Classic (`p_signature`, RSA) is a different scheme and is not
 * supported.
 *
 * @module
 */
import { concatBytes, payloadToBytes, utf8 } from '../internal/bytes.js';
import type { Bytes } from '../internal/bytes.js';
import { MAX_SIGNATURES_PER_HEADER, hmacSign, hmacVerifyAny } from '../internal/crypto.js';
import { bytesToHex, hexToBytes } from '../internal/encoding.js';
import { assertSignatureCount, malformedHeader, signatureMismatch } from '../internal/failures.js';
import { requireHeader } from '../internal/headers.js';
import { parseKeyValueList } from '../internal/parse.js';
import { secretList } from '../internal/secrets.js';
import {
  assertFresh,
  parseUnixSeconds,
  resolveTolerance,
  toUnixSeconds,
} from '../internal/timestamp.js';
import type {
  SignOptions,
  SignTimestampOptions,
  SignedHeaders,
  TimestampToleranceOptions,
  VerifyOptions,
} from '../types.js';

const PROVIDER = 'paddle';
const HEADER = 'paddle-signature';
const DEFAULT_TOLERANCE_SECONDS = 5;

/** Options for {@link verifyPaddle}. `secret` is the destination's `pdl_ntfset_...` key. */
export interface PaddleVerifyOptions extends VerifyOptions, TimestampToleranceOptions {}

/** A verified Paddle Billing webhook. */
export interface PaddleVerifyResult {
  readonly provider: 'paddle';
  /** The signed `ts` timestamp. */
  readonly timestamp: Date;
}

interface ParsedPaddleHeader {
  readonly timestampText: string;
  readonly timestamp: number;
  readonly signatures: readonly Bytes[];
}

function parseHeader(value: string): ParsedPaddleHeader {
  let timestampText: string | undefined;
  const signatures: Bytes[] = [];
  for (const [key, item] of parseKeyValueList(value, ';', PROVIDER, HEADER)) {
    if (key === 'ts') {
      if (timestampText !== undefined) {
        throw malformedHeader(PROVIDER, HEADER, 'Paddle-Signature contains more than one ts');
      }
      timestampText = item;
    } else if (key === 'h1') {
      const signature = hexToBytes(item, 32);
      if (signature === undefined) {
        throw malformedHeader(
          PROVIDER,
          HEADER,
          'Paddle-Signature h1 value is not 64 hex characters',
        );
      }
      signatures.push(signature);
    }
  }
  if (timestampText === undefined) {
    throw malformedHeader(PROVIDER, HEADER, 'Paddle-Signature has no ts= timestamp');
  }
  const timestamp = parseUnixSeconds(timestampText);
  if (timestamp === undefined) {
    throw malformedHeader(PROVIDER, HEADER, 'Paddle-Signature ts is not a Unix time');
  }
  if (signatures.length === 0) {
    throw malformedHeader(PROVIDER, HEADER, 'Paddle-Signature has no h1 signature');
  }
  assertSignatureCount(signatures.length, MAX_SIGNATURES_PER_HEADER, PROVIDER, HEADER);
  return { timestampText, timestamp, signatures };
}

/**
 * Verifies a Paddle Billing webhook (`Paddle-Signature` header).
 *
 * The default tolerance is Paddle's own 5 seconds. Verify as soon as the
 * request arrives (before queueing it), or pass a larger `toleranceSeconds`.
 *
 * @see https://developer.paddle.com/webhooks/signature-verification
 * @throws {@link WebhookVerificationError} when verification fails.
 */
export async function verifyPaddle(options: PaddleVerifyOptions): Promise<PaddleVerifyResult> {
  const window = resolveTolerance(options, DEFAULT_TOLERANCE_SECONDS);
  const secrets = secretList(options.secret, PROVIDER);
  const payload = payloadToBytes(options.payload);
  const header = parseHeader(requireHeader(options.headers, HEADER, PROVIDER, 'Paddle-Signature'));

  const message = concatBytes(utf8(`${header.timestampText}:`), payload);
  if (!(await hmacVerifyAny(secrets.map(utf8), message, header.signatures, 'SHA-256'))) {
    throw signatureMismatch(PROVIDER, HEADER, secrets);
  }
  assertFresh(header.timestamp, window, PROVIDER, HEADER);
  return { provider: PROVIDER, timestamp: new Date(header.timestamp * 1000) };
}

/** Options for {@link signPaddle}. */
export interface PaddleSignOptions extends SignOptions, SignTimestampOptions {}

/**
 * **Test utility.** Produces a `Paddle-Signature` header for `payload`, with
 * one `h1` per secret.
 */
export async function signPaddle(options: PaddleSignOptions): Promise<SignedHeaders> {
  const secrets = secretList(options.secret, PROVIDER);
  const timestamp = toUnixSeconds(options.timestamp);
  const message = concatBytes(utf8(`${timestamp}:`), payloadToBytes(options.payload));
  const parts = [`ts=${timestamp}`];
  for (const secret of secrets) {
    parts.push(`h1=${bytesToHex(await hmacSign(utf8(secret), message, 'SHA-256'))}`);
  }
  return { [HEADER]: parts.join(';') };
}
