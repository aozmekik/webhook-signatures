/**
 * Hono: read the raw body with `c.req.arrayBuffer()` before anything parses
 * it, verify, then parse. The same `app` runs on Workers (`export default
 * app`), Bun, Deno (`Deno.serve(app.fetch)`) and Node (`@hono/node-server`).
 */
import { Hono } from 'hono';
import { WebhookVerificationError, verifyStandardWebhook, verifyStripe } from 'webhook-signatures';
import { MemoryIdempotencyStore } from '../replay-protection/store.ts';

export interface Env {
  STRIPE_WEBHOOK_SECRET: string;
  RESEND_WEBHOOK_SECRET: string;
}

const processed = new MemoryIdempotencyStore();

export const app = new Hono<{ Bindings: Env }>();

app.post('/webhooks/stripe', async (c) => {
  const payload = await c.req.arrayBuffer();
  await verifyStripe({ payload, headers: c.req.raw.headers, secret: c.env.STRIPE_WEBHOOK_SECRET });
  const event = JSON.parse(new TextDecoder().decode(payload)) as { id: string; type: string };
  // Stripe event ids are inside the signed body: a sound idempotency key.
  if (!(await processed.claim(`stripe:${event.id}`, 3 * 24 * 3600))) {
    return c.json({ received: true, duplicate: true });
  }
  return c.json({ received: true, type: event.type });
});

// Resend (and Clerk) deliver through Svix: svix-id / svix-timestamp / svix-signature.
app.post('/webhooks/resend', async (c) => {
  const payload = await c.req.arrayBuffer();
  const { id } = await verifyStandardWebhook({
    payload,
    headers: c.req.raw.headers,
    secret: c.env.RESEND_WEBHOOK_SECRET,
  });
  if (!(await processed.claim(`resend:${id}`, 24 * 3600))) {
    return c.json({ received: true, duplicate: true });
  }
  const event = JSON.parse(new TextDecoder().decode(payload)) as { type: string };
  return c.json({ received: true, type: event.type });
});

app.onError((error, c) => {
  if (error instanceof WebhookVerificationError) {
    // Log the stable code; tell the sender as little as possible.
    console.warn(`webhook rejected: ${error.provider} ${error.code}`);
    return c.json({ error: 'invalid webhook signature' }, 400);
  }
  throw error;
});
