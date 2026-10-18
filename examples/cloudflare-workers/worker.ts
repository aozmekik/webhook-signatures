/**
 * Cloudflare Worker: one route for several providers, dispatched at runtime
 * with `verifyWebhook`. `request.arrayBuffer()` is the raw body.
 *
 * Run it with `npm run build`, then `npx wrangler dev` from
 * examples/cloudflare-workers (see wrangler.toml and examples/README.md).
 */
import { WebhookVerificationError, verifyWebhook } from 'webhook-signatures';
import type { ProviderId } from 'webhook-signatures';

export interface Env {
  STRIPE_WEBHOOK_SECRET: string;
  GITHUB_WEBHOOK_SECRET: string;
  SHOPIFY_CLIENT_SECRET: string;
}

const secrets = {
  stripe: (env: Env) => env.STRIPE_WEBHOOK_SECRET,
  github: (env: Env) => env.GITHUB_WEBHOOK_SECRET,
  shopify: (env: Env) => env.SHOPIFY_CLIENT_SECRET,
} satisfies Partial<Record<ProviderId, (env: Env) => string>>;

type RoutedProvider = keyof typeof secrets;

function isRouted(value: string): value is RoutedProvider {
  return Object.hasOwn(secrets, value);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const match = /^\/webhooks\/([a-z-]+)$/.exec(new URL(request.url).pathname);
    const provider = match?.[1];
    if (request.method !== 'POST' || provider === undefined || !isRouted(provider)) {
      return new Response('not found', { status: 404 });
    }
    const payload = await request.arrayBuffer();
    try {
      const result = await verifyWebhook(provider, {
        payload,
        headers: request.headers,
        secret: secrets[provider](env),
      });
      return Response.json({ received: true, provider: result.provider });
    } catch (error) {
      if (error instanceof WebhookVerificationError && error.code !== 'invalid_secret') {
        // Log the stable code; tell the sender as little as possible.
        console.warn(`rejected ${error.provider} webhook: ${error.code}`);
        return new Response('invalid webhook', { status: 400 });
      }
      // invalid_secret (for example a missing secret binding) and bugs become 500s.
      throw error;
    }
  },
};
