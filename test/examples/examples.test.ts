/**
 * Runs every example end to end with requests signed by the testing helpers,
 * so the recipes in the README cannot silently rot.
 */
import type { AddressInfo } from 'node:net';
import { describe, expect, it } from 'vitest';
import {
  signGitHub,
  signShopify,
  signSlack,
  signStandardWebhook,
  signStripe,
} from 'webhook-signatures/testing';
import worker from '../../examples/cloudflare-workers/worker.ts';
import { createHandler } from '../../examples/deno/handler.ts';
import { createApp } from '../../examples/express/app.ts';
import { app as honoApp } from '../../examples/hono/app.ts';
import { POST as nextStripeRoute } from '../../examples/nextjs/app/api/webhooks/stripe/route.ts';
import { MemoryIdempotencyStore } from '../../examples/replay-protection/store.ts';

const stripeEvent = JSON.stringify({ id: 'evt_example', type: 'checkout.session.completed' });

describe('Hono example', () => {
  const env = {
    STRIPE_WEBHOOK_SECRET: 'whsec_hono',
    RESEND_WEBHOOK_SECRET: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
  };

  it('accepts a signed Stripe event once and flags the redelivery', async () => {
    const headers = await signStripe({ payload: stripeEvent, secret: env.STRIPE_WEBHOOK_SECRET });
    const send = () =>
      honoApp.request('/webhooks/stripe', { method: 'POST', body: stripeEvent, headers }, env);
    expect(await (await send()).json()).toEqual({
      received: true,
      type: 'checkout.session.completed',
    });
    expect(await (await send()).json()).toEqual({ received: true, duplicate: true });
  });

  it('accepts a Resend (Svix) event and rejects a forged one', async () => {
    const body = JSON.stringify({ type: 'email.delivered' });
    const headers = await signStandardWebhook({
      payload: body,
      secret: env.RESEND_WEBHOOK_SECRET,
      id: 'msg_hono_1',
      headerPrefix: 'svix',
    });
    const ok = await honoApp.request('/webhooks/resend', { method: 'POST', body, headers }, env);
    expect(await ok.json()).toEqual({ received: true, type: 'email.delivered' });
    const forged = await honoApp.request(
      '/webhooks/resend',
      { method: 'POST', body: body.replace('delivered', 'bounced'), headers },
      env,
    );
    expect(forged.status).toBe(400);
  });
});

describe('Next.js route handler example', () => {
  it('verifies the raw body of a standard Request', async () => {
    process.env['STRIPE_WEBHOOK_SECRET'] = 'whsec_next';
    const headers = await signStripe({ payload: stripeEvent, secret: 'whsec_next' });
    const response = await nextStripeRoute(
      new Request('https://example.com/api/webhooks/stripe', {
        method: 'POST',
        body: stripeEvent,
        headers,
      }),
    );
    expect(await response.json()).toEqual({ received: true, type: 'checkout.session.completed' });

    const rejected = await nextStripeRoute(
      new Request('https://example.com/api/webhooks/stripe', { method: 'POST', body: stripeEvent }),
    );
    expect(rejected.status).toBe(400);
    expect(await rejected.json()).toEqual({ error: 'missing_header' });
  });
});

describe('Express example', () => {
  it('verifies express.raw() bodies over a real HTTP connection', async () => {
    const secret = 'express-secret';
    const server = createApp(secret).listen(0);
    await new Promise<void>((resolve) => server.once('listening', resolve));
    try {
      const { port } = server.address() as AddressInfo;
      const url = `http://127.0.0.1:${port}/webhooks/github`;
      const body = JSON.stringify({ action: 'opened' });
      const signed = await signGitHub({ payload: body, secret });
      const headers = { ...signed, 'content-type': 'application/json', 'x-github-event': 'issues' };

      const ok = await fetch(url, { method: 'POST', body, headers });
      expect(await ok.json()).toEqual({ received: true, event: 'issues', action: 'opened' });

      const bad = await fetch(url, { method: 'POST', body: `${body} `, headers });
      expect(bad.status).toBe(400);
      expect(await bad.json()).toEqual({ error: 'signature_mismatch' });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});

describe('Cloudflare Workers example', () => {
  const env = {
    STRIPE_WEBHOOK_SECRET: 'whsec_cf',
    GITHUB_WEBHOOK_SECRET: 'gh_cf',
    SHOPIFY_CLIENT_SECRET: 'shop_cf',
  };

  it('routes each provider to its verifier', async () => {
    const cases = [
      ['stripe', await signStripe({ payload: stripeEvent, secret: env.STRIPE_WEBHOOK_SECRET })],
      ['github', await signGitHub({ payload: stripeEvent, secret: env.GITHUB_WEBHOOK_SECRET })],
      ['shopify', await signShopify({ payload: stripeEvent, secret: env.SHOPIFY_CLIENT_SECRET })],
    ] as const;
    for (const [provider, headers] of cases) {
      const request = new Request(`https://worker.example/webhooks/${provider}`, {
        method: 'POST',
        body: stripeEvent,
        headers,
      });
      const response = await worker.fetch(request, env);
      expect(await response.json()).toEqual({ received: true, provider });
    }
  });

  it('rejects unknown routes and bad signatures', async () => {
    const unknown = await worker.fetch(
      new Request('https://worker.example/webhooks/paypal', { method: 'POST', body: '{}' }),
      env,
    );
    expect(unknown.status).toBe(404);
    const unsigned = await worker.fetch(
      new Request('https://worker.example/webhooks/github', { method: 'POST', body: '{}' }),
      env,
    );
    expect(await unsigned.json()).toEqual({ error: 'missing_header' });
  });
});

describe('Deno example', () => {
  it('verifies and then parses a form-encoded Slack command', async () => {
    const secret = 'slack-deno';
    const body = 'command=%2Fdeploy&text=prod';
    const headers = await signSlack({ payload: body, secret });
    const handler = createHandler(secret);
    const ok = await handler(
      new Request('https://deno.example/slack', { method: 'POST', body, headers }),
    );
    expect(await ok.json()).toEqual({ response_type: 'ephemeral', text: 'You ran /deploy' });
    const bad = await handler(
      new Request('https://deno.example/slack', { method: 'POST', body, headers: {} }),
    );
    expect(bad.status).toBe(401);
  });
});

describe('replay protection store', () => {
  it('claims an id once per TTL window', async () => {
    let now = 0;
    const store = new MemoryIdempotencyStore(() => now);
    expect(await store.claim('evt_1', 60)).toBe(true);
    expect(await store.claim('evt_1', 60)).toBe(false);
    now = 61_000;
    expect(await store.claim('evt_1', 60)).toBe(true);
  });
});
