/**
 * One adapter per provider, so that behaviour every scheme must share
 * (round trips, tampering, wrong secrets, rotation, header casing, payload
 * types, replay windows) is tested once, table-driven, in conformance.test.ts.
 */
import {
  verifyGitHub,
  verifyLemonSqueezy,
  verifyPaddle,
  verifyShopify,
  verifySlack,
  verifyStandardWebhook,
  verifyStripe,
  verifyTwilio,
} from 'webhook-signatures';
import type { HeadersInput, ProviderId, SecretInput, WebhookPayload } from 'webhook-signatures';
import {
  signGitHub,
  signLemonSqueezy,
  signPaddle,
  signShopify,
  signSlack,
  signStandardWebhook,
  signStripe,
  signTwilio,
} from 'webhook-signatures/testing';

export const TWILIO_URL = 'https://example.com/twilio/voice?tenant=acme';

export interface SignInput {
  readonly payload: WebhookPayload;
  readonly secret: SecretInput;
  readonly timestamp?: Date;
}

export interface VerifyInput {
  readonly payload: WebhookPayload;
  readonly headers: HeadersInput;
  readonly secret: SecretInput;
  readonly now?: Date;
  readonly toleranceSeconds?: number;
}

export interface ProviderCase {
  readonly id: ProviderId;
  /** Header that carries the signature. */
  readonly signatureHeader: string;
  /** Present for schemes that sign a timestamp. */
  readonly timestamp?: { readonly header: string; readonly defaultToleranceSeconds: number };
  /** Whether signing with a list of secrets emits one signature per secret. */
  readonly multiSignature: boolean;
  /** A realistic secret and a different, equally valid one. */
  readonly secret: string;
  readonly otherSecret: string;
  /** A realistic body for this provider. */
  readonly samplePayload: string;
  sign(input: SignInput): Promise<Record<string, string>>;
  verify(input: VerifyInput): Promise<unknown>;
}

const json = JSON.stringify({
  id: 'evt_123',
  type: 'demo.created',
  data: { amount: 4200, note: 'çağrı ✓' },
});

export const providerCases: readonly ProviderCase[] = [
  {
    id: 'stripe',
    signatureHeader: 'stripe-signature',
    timestamp: { header: 'stripe-signature', defaultToleranceSeconds: 300 },
    multiSignature: true,
    secret: 'whsec_test_5WbX5kEWLlfzsGNjH64I8lOOqUB6e8FH',
    otherSecret: 'whsec_test_rotated_0123456789abcdef',
    samplePayload: json,
    sign: (input) => signStripe(input),
    verify: (input) => verifyStripe(input),
  },
  {
    id: 'github',
    signatureHeader: 'x-hub-signature-256',
    multiSignature: false,
    secret: "It's a Secret to Everybody",
    otherSecret: 'another-github-secret',
    samplePayload: JSON.stringify({
      action: 'opened',
      number: 1,
      repository: { full_name: 'o/r' },
    }),
    sign: (input) => signGitHub(input),
    verify: (input) => verifyGitHub(input),
  },
  {
    id: 'slack',
    signatureHeader: 'x-slack-signature',
    timestamp: { header: 'x-slack-request-timestamp', defaultToleranceSeconds: 300 },
    multiSignature: false,
    secret: '8f742231b10e8888abcd99yyyzzz85a5',
    otherSecret: '00000000000000000000000000000000',
    samplePayload: 'token=abc&team_id=T1&command=%2Fdeploy&text=prod+now',
    sign: (input) => signSlack(input),
    verify: (input) => verifySlack(input),
  },
  {
    id: 'shopify',
    signatureHeader: 'x-shopify-hmac-sha256',
    multiSignature: false,
    secret: 'shpss_client_secret_for_tests',
    otherSecret: 'shpss_rotated_client_secret',
    samplePayload: JSON.stringify({ id: 820982911946154500, email: 'jon@example.com' }),
    sign: (input) => signShopify(input),
    verify: (input) => verifyShopify(input),
  },
  {
    id: 'standard-webhooks',
    signatureHeader: 'webhook-signature',
    timestamp: { header: 'webhook-timestamp', defaultToleranceSeconds: 300 },
    multiSignature: true,
    secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
    otherSecret: 'whsec_plJ3nmyCDGBKInavdOK15jsl',
    samplePayload: json,
    sign: (input) => signStandardWebhook({ ...input, id: 'msg_2KWPBgLlAfxdpx2AI54pPJ85f4W' }),
    verify: (input) => verifyStandardWebhook(input),
  },
  {
    id: 'twilio',
    signatureHeader: 'x-twilio-signature',
    multiSignature: false,
    secret: '12345abcdef12345abcdef12345abcde',
    otherSecret: 'fedcba54321fedcba54321fedcba5432',
    samplePayload: 'CallSid=CA1234567890ABCDE&Caller=%2B14158675310&Digits=1234&To=%2B18005551212',
    sign: async (input) => (await signTwilio({ ...input, url: TWILIO_URL })).headers,
    verify: (input) => verifyTwilio({ ...input, url: TWILIO_URL }),
  },
  {
    id: 'paddle',
    signatureHeader: 'paddle-signature',
    timestamp: { header: 'paddle-signature', defaultToleranceSeconds: 5 },
    multiSignature: true,
    secret: 'pdl_ntfset_01gkpjp8bkm3tm53kdgkx6sms7_6h3qd3uFSi9YCD3OLYAShQI90XTI5vEI',
    otherSecret: 'pdl_ntfset_01gkpjp8bkm3tm53kdgkx6sms7_rotatedrotatedrotated',
    samplePayload: JSON.stringify({ event_id: 'evt_01', event_type: 'transaction.completed' }),
    sign: (input) => signPaddle(input),
    verify: (input) => verifyPaddle(input),
  },
  {
    id: 'lemon-squeezy',
    signatureHeader: 'x-signature',
    multiSignature: false,
    secret: 'lemon-signing-secret',
    otherSecret: 'lemon-rotated-secret',
    samplePayload: JSON.stringify({ meta: { event_name: 'order_created' }, data: { id: '1' } }),
    sign: (input) => signLemonSqueezy(input),
    verify: (input) => verifyLemonSqueezy(input),
  },
];
