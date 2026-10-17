/**
 * Header-parsing edge cases: every documented header format, and the ways it
 * can be broken. A well-formed header that does not match is a
 * `signature_mismatch`; anything that does not parse is a `malformed_header`.
 */
import { describe, it } from 'vitest';
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
import type { WebhookVerificationErrorCode } from 'webhook-signatures';
import { NOW, expectCode } from '../support/assertions.js';

const payload = '{"ok":true}';
const t = String(NOW.getTime() / 1000);
const hex64 = 'ab'.repeat(32);
const b64of32 = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));
// 0xfb bytes encode to "+/v7..." in standard base64, so the URL-safe variant differs.
const urlSafeB64of32 = btoa(String.fromCharCode(...new Uint8Array(32).fill(0xfb)))
  .replaceAll('+', '-')
  .replaceAll('/', '_');
const b64of20 = btoa(String.fromCharCode(...new Uint8Array(20).fill(7)));

type Case = readonly [label: string, value: string, code: WebhookVerificationErrorCode];

function suite(
  name: string,
  cases: readonly Case[],
  verify: (value: string) => Promise<unknown>,
): void {
  describe(name, () => {
    it.each(cases)('%s', async (_label, value, code) => {
      await expectCode(verify(value), code);
    });
  });
}

suite(
  'Stripe-Signature',
  [
    ['no key=value pairs', 'garbage', 'malformed_header'],
    ['empty element', `t=${t},,v1=${hex64}`, 'malformed_header'],
    ['missing key', `=${t},v1=${hex64}`, 'malformed_header'],
    ['no timestamp', `v1=${hex64}`, 'malformed_header'],
    ['two timestamps', `t=${t},t=${t},v1=${hex64}`, 'malformed_header'],
    ['non-numeric timestamp', `t=soon,v1=${hex64}`, 'malformed_header'],
    ['negative timestamp', `t=-1,v1=${hex64}`, 'malformed_header'],
    ['fractional timestamp', `t=${t}.5,v1=${hex64}`, 'malformed_header'],
    ['exponent timestamp', `t=1e9,v1=${hex64}`, 'malformed_header'],
    ['only a v0 test signature', `t=${t},v0=${hex64}`, 'malformed_header'],
    ['only an unknown scheme', `t=${t},v2=${hex64}`, 'malformed_header'],
    ['short v1', `t=${t},v1=${hex64.slice(2)}`, 'malformed_header'],
    ['non-hex v1', `t=${t},v1=${'zz'.repeat(32)}`, 'malformed_header'],
    ['too many v1 values', `t=${t},${Array(11).fill(`v1=${hex64}`).join(',')}`, 'malformed_header'],
    ['well-formed but wrong', `t=${t},v1=${hex64}`, 'signature_mismatch'],
    [
      'ten wrong v1 values',
      `t=${t},${Array(10).fill(`v1=${hex64}`).join(',')}`,
      'signature_mismatch',
    ],
    [
      'wrong v1 next to v0 and unknown schemes',
      `t=${t},v1=${hex64},v0=${hex64},v9=x`,
      'signature_mismatch',
    ],
  ],
  (value) =>
    verifyStripe({ payload, headers: { 'stripe-signature': value }, secret: 'whsec_x', now: NOW }),
);

suite(
  'X-Hub-Signature-256',
  [
    ['bare hex without prefix', hex64, 'malformed_header'],
    ['sha1 prefix', `sha1=${hex64.slice(0, 40)}`, 'malformed_header'],
    ['upper-case prefix', `SHA256=${hex64}`, 'malformed_header'],
    ['short digest', `sha256=${hex64.slice(1)}`, 'malformed_header'],
    ['well-formed but wrong', `sha256=${hex64}`, 'signature_mismatch'],
    ['upper-case hex but wrong', `sha256=${hex64.toUpperCase()}`, 'signature_mismatch'],
  ],
  (value) => verifyGitHub({ payload, headers: { 'x-hub-signature-256': value }, secret: 's' }),
);

suite(
  'X-Slack-Signature',
  [
    ['no version', hex64, 'malformed_header'],
    ['unknown version', `v1=${hex64}`, 'malformed_header'],
    ['short digest', `v0=${hex64.slice(2)}`, 'malformed_header'],
    ['well-formed but wrong', `v0=${hex64}`, 'signature_mismatch'],
  ],
  (value) =>
    verifySlack({
      payload,
      headers: { 'x-slack-signature': value, 'x-slack-request-timestamp': t },
      secret: 's',
      now: NOW,
    }),
);

suite(
  'X-Slack-Request-Timestamp',
  [
    ['not a number', 'yesterday', 'malformed_header'],
    ['milliseconds with a dot', `${t}.000`, 'malformed_header'],
    ['thirteen digits', '1700000000000', 'malformed_header'],
  ],
  (value) =>
    verifySlack({
      payload,
      headers: { 'x-slack-signature': `v0=${hex64}`, 'x-slack-request-timestamp': value },
      secret: 's',
      now: NOW,
    }),
);

suite(
  'X-Shopify-Hmac-SHA256',
  [
    ['hex instead of base64', hex64, 'malformed_header'],
    ['url-safe alphabet', urlSafeB64of32, 'malformed_header'],
    ['truncated base64', b64of32.slice(0, 20), 'malformed_header'],
    ['bad padding', `${b64of32.replace(/=+$/, '')}===`, 'malformed_header'],
    ['inner whitespace', `${b64of32.slice(0, 8)} ${b64of32.slice(8)}`, 'malformed_header'],
    ['well-formed but wrong', b64of32, 'signature_mismatch'],
    ['unpadded but wrong', b64of32.replace(/=+$/, ''), 'signature_mismatch'],
  ],
  (value) => verifyShopify({ payload, headers: { 'x-shopify-hmac-sha256': value }, secret: 's' }),
);

suite(
  'webhook-signature',
  [
    ['no version prefix', b64of32, 'malformed_header'],
    ['leading comma', `,${b64of32}`, 'malformed_header'],
    ['only asymmetric v1a', `v1a,${b64of32}`, 'malformed_header'],
    ['blank entries only', ' ', 'missing_header'],
    ['bad base64', 'v1,@@@@', 'malformed_header'],
    ['wrong digest length', 'v1,AAAA', 'malformed_header'],
    ['too many v1 values', Array(11).fill(`v1,${b64of32}`).join(' '), 'malformed_header'],
    ['well-formed but wrong', `v1,${b64of32}`, 'signature_mismatch'],
    ['wrong v1 among v1a and double spaces', `v1a,xyz  v1,${b64of32}`, 'signature_mismatch'],
  ],
  (value) =>
    verifyStandardWebhook({
      payload,
      headers: { 'webhook-id': 'msg_1', 'webhook-timestamp': t, 'webhook-signature': value },
      secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
      now: NOW,
    }),
);

suite(
  'webhook-timestamp',
  [
    ['not a number', 'now', 'malformed_header'],
    ['ISO date', NOW.toISOString(), 'malformed_header'],
  ],
  (value) =>
    verifyStandardWebhook({
      payload,
      headers: {
        'webhook-id': 'msg_1',
        'webhook-timestamp': value,
        'webhook-signature': `v1,${b64of32}`,
      },
      secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
      now: NOW,
    }),
);

suite(
  'X-Twilio-Signature',
  [
    ['hex instead of base64', hex64.slice(0, 40), 'malformed_header'],
    ['SHA-256 length', b64of32, 'malformed_header'],
    ['well-formed but wrong', b64of20, 'signature_mismatch'],
  ],
  (value) =>
    verifyTwilio({
      payload: 'A=1',
      headers: { 'x-twilio-signature': value },
      secret: 'token',
      url: 'https://example.com/hook',
    }),
);

suite(
  'Paddle-Signature',
  [
    ['comma separated', `ts=${t},h1=${hex64}`, 'malformed_header'],
    ['no timestamp', `h1=${hex64}`, 'malformed_header'],
    ['two timestamps', `ts=${t};ts=${t};h1=${hex64}`, 'malformed_header'],
    ['bad timestamp', `ts=now;h1=${hex64}`, 'malformed_header'],
    ['no h1', `ts=${t}`, 'malformed_header'],
    ['short h1', `ts=${t};h1=abc`, 'malformed_header'],
    [
      'too many h1 values',
      `ts=${t};${Array(11).fill(`h1=${hex64}`).join(';')}`,
      'malformed_header',
    ],
    ['well-formed but wrong', `ts=${t};h1=${hex64}`, 'signature_mismatch'],
    ['wrong h1 with unknown keys and spaces', `ts=${t}; h1=${hex64}; h2=zzz`, 'signature_mismatch'],
  ],
  (value) =>
    verifyPaddle({ payload, headers: { 'paddle-signature': value }, secret: 'pdl_x', now: NOW }),
);

suite(
  'X-Signature (Lemon Squeezy)',
  [
    ['prefixed like GitHub', `sha256=${hex64}`, 'malformed_header'],
    ['base64', b64of32, 'malformed_header'],
    ['well-formed but wrong', hex64, 'signature_mismatch'],
  ],
  (value) => verifyLemonSqueezy({ payload, headers: { 'x-signature': value }, secret: 's' }),
);
