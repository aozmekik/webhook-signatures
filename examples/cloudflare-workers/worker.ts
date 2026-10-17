/**
 * Cloudflare Worker: one route for several providers, dispatched at runtime
 * with `verifyWebhook`. `request.arrayBuffer()` is the raw body.
 *
 *   wrangler dev examples/cloudflare-workers/worker.ts
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
      if (error instanceof WebhookVerificationError) {
        return Response.json({ error: error.code }, { status: 400 });
      }
      throw error;
    }
  },
};
