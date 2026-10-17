/**
 * **Test utilities.** Each `sign*` helper produces the headers a provider
 * would send for a given body and secret, so webhook handlers can be tested
 * end to end without network access or provider CLIs.
 *
 * These helpers exist for tests and local development. Production code only
 * needs the `verify*` functions from `webhook-signatures`.
 *
 * @example
 * ```ts
 * import { signStripe } from 'webhook-signatures/testing';
 *
 * const body = JSON.stringify({ id: 'evt_test', type: 'payment_intent.succeeded' });
 * const headers = await signStripe({ payload: body, secret: 'whsec_test_secret' });
 * const response = await app.request('/webhooks/stripe', { method: 'POST', body, headers });
 * ```
 *
 * @packageDocumentation
 */
export type {
  SecretInput,
  SignOptions,
  SignTimestampOptions,
  SignedHeaders,
  WebhookPayload,
} from './types.js';

export { signGitHub } from './providers/github.js';
export type { GitHubSignOptions } from './providers/github.js';
export { signLemonSqueezy } from './providers/lemon-squeezy.js';
export type { LemonSqueezySignOptions } from './providers/lemon-squeezy.js';
export { signPaddle } from './providers/paddle.js';
export type { PaddleSignOptions } from './providers/paddle.js';
export { signShopify } from './providers/shopify.js';
export type { ShopifySignOptions } from './providers/shopify.js';
export { signSlack } from './providers/slack.js';
export type { SlackSignOptions } from './providers/slack.js';
export { signStandardWebhook } from './providers/standard-webhooks.js';
export type { StandardWebhookSignOptions } from './providers/standard-webhooks.js';
export { signStripe } from './providers/stripe.js';
export type { StripeSignOptions } from './providers/stripe.js';
export { signTwilio } from './providers/twilio.js';
export type { TwilioSignOptions, TwilioSignedRequest } from './providers/twilio.js';
