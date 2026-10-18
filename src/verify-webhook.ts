import { verifyGitHub } from './providers/github.js';
import type { GitHubVerifyOptions, GitHubVerifyResult } from './providers/github.js';
import { verifyLemonSqueezy } from './providers/lemon-squeezy.js';
import type {
  LemonSqueezyVerifyOptions,
  LemonSqueezyVerifyResult,
} from './providers/lemon-squeezy.js';
import { verifyPaddle } from './providers/paddle.js';
import type { PaddleVerifyOptions, PaddleVerifyResult } from './providers/paddle.js';
import { verifyShopify } from './providers/shopify.js';
import type { ShopifyVerifyOptions, ShopifyVerifyResult } from './providers/shopify.js';
import { verifySlack } from './providers/slack.js';
import type { SlackVerifyOptions, SlackVerifyResult } from './providers/slack.js';
import { verifyStandardWebhook } from './providers/standard-webhooks.js';
import type {
  StandardWebhookVerifyOptions,
  StandardWebhookVerifyResult,
} from './providers/standard-webhooks.js';
import { verifyStripe } from './providers/stripe.js';
import type { StripeVerifyOptions, StripeVerifyResult } from './providers/stripe.js';
import { verifyTwilio } from './providers/twilio.js';
import type { TwilioVerifyOptions, TwilioVerifyResult } from './providers/twilio.js';
import type { ProviderId } from './types.js';

/** Maps each {@link ProviderId} to its verify options and result types. */
export interface WebhookProviders {
  stripe: { options: StripeVerifyOptions; result: StripeVerifyResult };
  github: { options: GitHubVerifyOptions; result: GitHubVerifyResult };
  slack: { options: SlackVerifyOptions; result: SlackVerifyResult };
  shopify: { options: ShopifyVerifyOptions; result: ShopifyVerifyResult };
  'standard-webhooks': {
    options: StandardWebhookVerifyOptions;
    result: StandardWebhookVerifyResult;
  };
  twilio: { options: TwilioVerifyOptions; result: TwilioVerifyResult };
  paddle: { options: PaddleVerifyOptions; result: PaddleVerifyResult };
  'lemon-squeezy': { options: LemonSqueezyVerifyOptions; result: LemonSqueezyVerifyResult };
}

/** The intersection of the members of union `U` (`U` itself when it is not a union). */
type Intersection<U> = (U extends unknown ? (value: U) => void : never) extends (
  value: infer I,
) => void
  ? I
  : never;

/**
 * Options accepted by {@link verifyWebhook} for provider `P`.
 *
 * When `P` is a union, because the provider is only known at runtime, the
 * options must be valid for every provider in it: `url` is required as soon
 * as `P` includes `'twilio'`. Options that only some providers use, such as
 * `toleranceSeconds`, are ignored by the others.
 */
export type VerifyWebhookOptions<P extends ProviderId> = Intersection<
  WebhookProviders[P]['options']
>;

/**
 * Result returned by {@link verifyWebhook} for provider `P`; a union of
 * results when `P` is a union.
 */
export type VerifyWebhookResult<P extends ProviderId> = WebhookProviders[P]['result'];

type Verifiers = {
  readonly [P in ProviderId]: (options: VerifyWebhookOptions<P>) => Promise<VerifyWebhookResult<P>>;
};

const verifiers: Verifiers = {
  stripe: verifyStripe,
  github: verifyGitHub,
  slack: verifySlack,
  shopify: verifyShopify,
  'standard-webhooks': verifyStandardWebhook,
  twilio: verifyTwilio,
  paddle: verifyPaddle,
  'lemon-squeezy': verifyLemonSqueezy,
};

/**
 * Verifies a webhook for the provider named at runtime, for example from a
 * route parameter. The options and result are typed per provider; with a
 * union of providers the options must suit all of them (see
 * {@link VerifyWebhookOptions}).
 *
 * This references every verifier, so bundles that use it include all
 * providers. Import the specific `verify*` function instead when the provider
 * is known statically.
 *
 * @example
 * ```ts
 * const result = await verifyWebhook('github', { payload, headers, secret });
 * result.deliveryId; // typed as GitHubVerifyResult
 * ```
 *
 * @throws {@link WebhookVerificationError} when verification fails.
 * @throws TypeError when `provider` is not a supported {@link ProviderId}.
 */
export function verifyWebhook<P extends ProviderId>(
  provider: P,
  options: VerifyWebhookOptions<P>,
): Promise<VerifyWebhookResult<P>> {
  const id: unknown = provider;
  if (typeof id !== 'string' || !Object.hasOwn(verifiers, id)) {
    return Promise.reject(new TypeError(`Unsupported webhook provider: ${String(id)}`));
  }
  // TypeScript cannot correlate `verifiers[provider]` with `options` for a
  // generic `P`; the mapped type above guarantees they agree.
  const verify = verifiers[provider] as (
    options: VerifyWebhookOptions<P>,
  ) => Promise<VerifyWebhookResult<P>>;
  return verify(options);
}
