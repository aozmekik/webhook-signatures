/**
 * Verify webhook signatures with nothing but the Web Crypto API.
 *
 * Every verifier takes the raw body, the request headers and the secret, and
 * either resolves with a typed result or rejects with a
 * {@link WebhookVerificationError} carrying a stable `code`.
 *
 * Signing helpers for tests live in `webhook-signatures/testing`.
 *
 * @packageDocumentation
 */
export { WebhookVerificationError } from './errors.js';
export type { WebhookVerificationErrorCode, WebhookVerificationErrorOptions } from './errors.js';
export type {
  HeadersInput,
  ProviderId,
  SecretInput,
  TimestampToleranceOptions,
  VerifyOptions,
  WebhookPayload,
} from './types.js';

export { verifyGitHub } from './providers/github.js';
export type { GitHubVerifyOptions, GitHubVerifyResult } from './providers/github.js';
export { verifyLemonSqueezy } from './providers/lemon-squeezy.js';
export type {
  LemonSqueezyVerifyOptions,
  LemonSqueezyVerifyResult,
} from './providers/lemon-squeezy.js';
export { verifyPaddle } from './providers/paddle.js';
export type { PaddleVerifyOptions, PaddleVerifyResult } from './providers/paddle.js';
export { verifyShopify } from './providers/shopify.js';
export type { ShopifyVerifyOptions, ShopifyVerifyResult } from './providers/shopify.js';
export { verifySlack } from './providers/slack.js';
export type { SlackVerifyOptions, SlackVerifyResult } from './providers/slack.js';
export { verifyStandardWebhook } from './providers/standard-webhooks.js';
export type {
  StandardWebhookVerifyOptions,
  StandardWebhookVerifyResult,
} from './providers/standard-webhooks.js';
export { verifyStripe } from './providers/stripe.js';
export type { StripeVerifyOptions, StripeVerifyResult } from './providers/stripe.js';
export { verifyTwilio } from './providers/twilio.js';
export type { TwilioVerifyOptions, TwilioVerifyResult } from './providers/twilio.js';

export { verifyWebhook } from './verify-webhook.js';
export type {
  VerifyWebhookOptions,
  VerifyWebhookResult,
  WebhookProviders,
} from './verify-webhook.js';
