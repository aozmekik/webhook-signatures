/**
 * Hono: read the raw body with `c.req.arrayBuffer()` before anything parses
 * it, verify, then parse.
 *
 * Secrets are read from `c.env`, which holds the bindings on Cloudflare
 * Workers (`export default createApp(handleEvent)`). Other runtimes have no
 * bindings, so pass the secrets as the `env` argument of `app.fetch`:
 *
 *   // Node.js (@hono/node-server) or Bun
 *   serve({ fetch: (request) => app.fetch(request, { STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET, ... }) });
 *   // Deno
 *   Deno.serve((request) => app.fetch(request, Deno.env.toObject()));
 */
import { Hono } from 'hono';
import type { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { WebhookVerificationError, verifyStandardWebhook, verifyStripe } from 'webhook-signatures';
import { MemoryIdempotencyStore, processOnce } from '../replay-protection/store.ts';
import type { IdempotencyStore } from '../replay-protection/store.ts';

export interface Env {
  STRIPE_WEBHOOK_SECRET: string;
  RESEND_WEBHOOK_SECRET: string;
}

/** A verified event, handed to your code. */
export interface WebhookEvent {
  readonly provider: 'stripe' | 'resend';
  readonly type: string;
  readonly payload: unknown;
}

const DAY = 24 * 3600;

function respond(
  c: Context,
  outcome: 'processed' | 'duplicate' | 'in-progress',
  type: string,
): Response {
  if (outcome === 'in-progress') {
    // Another delivery of the same event is being processed: a non-2xx
    // answer makes the provider retry later instead of dropping it.
    return c.json({ error: 'already being processed' }, 409);
  }
  return c.json(
    outcome === 'duplicate' ? { received: true, duplicate: true } : { received: true, type },
  );
}

/**
 * @param handleEvent - Your side effects. If it throws, the event's id is
 *   released, the response is a 500, and the provider's retry is processed.
 * @param store - Shared idempotency store; in-memory by default.
 */
export function createApp(
  handleEvent: (event: WebhookEvent) => Promise<void>,
  store: IdempotencyStore = new MemoryIdempotencyStore(),
): Hono<{ Bindings: Env }> {
  const app = new Hono<{ Bindings: Env }>();

  app.post('/webhooks/stripe', async (c) => {
    const payload = await c.req.arrayBuffer();
    await verifyStripe({
      payload,
      headers: c.req.raw.headers,
      secret: c.env.STRIPE_WEBHOOK_SECRET,
    });
    const event = JSON.parse(new TextDecoder().decode(payload)) as { id: string; type: string };
    // Stripe event ids are inside the signed body: a sound idempotency key.
    const outcome = await processOnce(
      store,
      `stripe:${event.id}`,
      { leaseSeconds: 60, ttlSeconds: 3 * DAY },
      () => handleEvent({ provider: 'stripe', type: event.type, payload: event }),
    );
    return respond(c, outcome, event.type);
  });

  // Resend (and Clerk) deliver through Svix: svix-id / svix-timestamp / svix-signature.
  app.post('/webhooks/resend', async (c) => {
    const payload = await c.req.arrayBuffer();
    const { id } = await verifyStandardWebhook({
      payload,
      headers: c.req.raw.headers,
      secret: c.env.RESEND_WEBHOOK_SECRET,
    });
    const event = JSON.parse(new TextDecoder().decode(payload)) as { type: string };
    // The Standard Webhooks message id is part of the signed content.
    const outcome = await processOnce(
      store,
      `resend:${id}`,
      { leaseSeconds: 60, ttlSeconds: DAY },
      () => handleEvent({ provider: 'resend', type: event.type, payload: event }),
    );
    return respond(c, outcome, event.type);
  });

  app.onError((error, c) => {
    // invalid_secret means this deployment is misconfigured: a 500, not a 400.
    if (error instanceof WebhookVerificationError && error.code !== 'invalid_secret') {
      // Log the stable code; tell the sender as little as possible.
      console.warn(`webhook rejected: ${error.provider} ${error.code}`);
      return c.json({ error: 'invalid webhook' }, 400);
    }
    if (error instanceof HTTPException) {
      return error.getResponse();
    }
    console.error(error);
    return c.text('Internal Server Error', 500);
  });

  return app;
}
