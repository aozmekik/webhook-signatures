/**
 * Runs every example end to end with requests signed by the testing helpers,
 * so the recipes in the README cannot silently rot.
 */
import type { AddressInfo } from 'node:net';
import { HTTPException } from 'hono/http-exception';
import { describe, expect, it, vi } from 'vitest';
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
import { createApp as createHonoApp } from '../../examples/hono/app.ts';
import type { WebhookEvent } from '../../examples/hono/app.ts';
import { POST as nextStripeRoute } from '../../examples/nextjs/app/api/webhooks/stripe/route.ts';
import { MemoryIdempotencyStore, processOnce } from '../../examples/replay-protection/store.ts';

const stripeEvent = JSON.stringify({ id: 'evt_example', type: 'checkout.session.completed' });

/** Silences and records the warnings the examples log for rejected webhooks. */
function captureWarnings(): () => string[] {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
  return () => warn.mock.calls.map((args) => args.join(' '));
}

describe('Hono example', () => {
  const env = {
    STRIPE_WEBHOOK_SECRET: 'whsec_hono',
    RESEND_WEBHOOK_SECRET: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
  };

  it('processes a signed Stripe event once and acknowledges the redelivery', async () => {
    const handled: WebhookEvent[] = [];
    const app = createHonoApp((event) => {
      handled.push(event);
      return Promise.resolve();
    });
    const headers = await signStripe({ payload: stripeEvent, secret: env.STRIPE_WEBHOOK_SECRET });
    const send = () =>
      app.request('/webhooks/stripe', { method: 'POST', body: stripeEvent, headers }, env);
    expect(await (await send()).json()).toEqual({
      received: true,
      type: 'checkout.session.completed',
    });
    expect(await (await send()).json()).toEqual({ received: true, duplicate: true });
    expect(handled.map((event) => event.type)).toEqual(['checkout.session.completed']);
  });

  it('processes the retry when handling failed, instead of dropping the event', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    let attempts = 0;
    const app = createHonoApp(() => {
      attempts++;
      return attempts === 1 ? Promise.reject(new Error('database down')) : Promise.resolve();
    });
    const headers = await signStripe({ payload: stripeEvent, secret: env.STRIPE_WEBHOOK_SECRET });
    const send = () =>
      app.request('/webhooks/stripe', { method: 'POST', body: stripeEvent, headers }, env);
    expect((await send()).status).toBe(500);
    expect(errors).toHaveBeenCalledOnce();
    expect(await (await send()).json()).toEqual({
      received: true,
      type: 'checkout.session.completed',
    });
    expect(attempts).toBe(2);
  });

  it('accepts a Resend (Svix) event and rejects a forged one without revealing why', async () => {
    const warnings = captureWarnings();
    const app = createHonoApp(() => Promise.resolve());
    const body = JSON.stringify({ type: 'email.delivered' });
    const headers = await signStandardWebhook({
      payload: body,
      secret: env.RESEND_WEBHOOK_SECRET,
      id: 'msg_hono_1',
      headerPrefix: 'svix',
    });
    const ok = await app.request('/webhooks/resend', { method: 'POST', body, headers }, env);
    expect(await ok.json()).toEqual({ received: true, type: 'email.delivered' });
    const forged = await app.request(
      '/webhooks/resend',
      { method: 'POST', body: body.replace('delivered', 'bounced'), headers },
      env,
    );
    expect(forged.status).toBe(400);
    expect(await forged.json()).toEqual({ error: 'invalid webhook' });
    expect(warnings()).toEqual(['webhook rejected: standard-webhooks signature_mismatch']);
  });

  it('answers a missing secret with a 500, not a 400', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const app = createHonoApp(() => Promise.resolve());
    const headers = await signStripe({ payload: stripeEvent, secret: env.STRIPE_WEBHOOK_SECRET });
    const response = await app.request(
      '/webhooks/stripe',
      { method: 'POST', body: stripeEvent, headers },
      { ...env, STRIPE_WEBHOOK_SECRET: '' },
    );
    expect(response.status).toBe(500);
    expect(errors.mock.calls[0]?.[0]).toMatchObject({ code: 'invalid_secret' });
  });

  it('turns other errors into a plain 500 and passes HTTP exceptions through', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const app = createHonoApp(() =>
      Promise.reject(new HTTPException(503, { message: 'maintenance' })),
    );
    // A body that is signed but not JSON fails after verification: a 500.
    const body = 'not json';
    const signed = await signStripe({ payload: body, secret: env.STRIPE_WEBHOOK_SECRET });
    const broken = await app.request(
      '/webhooks/stripe',
      { method: 'POST', body, headers: signed },
      env,
    );
    expect(broken.status).toBe(500);
    expect(errors).toHaveBeenCalledOnce();
    // An HTTPException thrown by the handler keeps its own response.
    const headers = await signStripe({ payload: stripeEvent, secret: env.STRIPE_WEBHOOK_SECRET });
    const response = await app.request(
      '/webhooks/stripe',
      { method: 'POST', body: stripeEvent, headers },
      env,
    );
    expect(response.status).toBe(503);
    expect(await response.text()).toBe('maintenance');
  });
});

describe('Next.js route handler example', () => {
  it('verifies the raw body of a standard Request', async () => {
    const warnings = captureWarnings();
    vi.stubEnv('STRIPE_WEBHOOK_SECRET', 'whsec_next');
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
    expect(await rejected.text()).toBe('invalid webhook');
    expect(warnings()).toEqual(['rejected stripe webhook: missing_header']);
  });

  it('throws (a 500 in Next.js) when the secret is not configured', async () => {
    vi.stubEnv('STRIPE_WEBHOOK_SECRET', '');
    await expect(
      nextStripeRoute(new Request('https://example.com/api/webhooks/stripe', { method: 'POST' })),
    ).rejects.toThrow('STRIPE_WEBHOOK_SECRET is not set');
  });
});

describe('Express example', () => {
  it('verifies express.raw() bodies over a real HTTP connection', async () => {
    const warnings = captureWarnings();
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
      expect(await bad.json()).toEqual({ error: 'invalid webhook' });
      expect(warnings()).toEqual(['rejected github webhook: signature_mismatch']);
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
    const warnings = captureWarnings();
    const unknown = await worker.fetch(
      new Request('https://worker.example/webhooks/paypal', { method: 'POST', body: '{}' }),
      env,
    );
    expect(unknown.status).toBe(404);
    const unsigned = await worker.fetch(
      new Request('https://worker.example/webhooks/github', { method: 'POST', body: '{}' }),
      env,
    );
    expect(unsigned.status).toBe(400);
    expect(await unsigned.text()).toBe('invalid webhook');
    expect(warnings()).toEqual(['rejected github webhook: missing_header']);
  });

  it('lets a missing secret binding surface as an error (a 500 on Workers)', async () => {
    const headers = await signGitHub({ payload: '{}', secret: 'gh_cf' });
    await expect(
      worker.fetch(
        new Request('https://worker.example/webhooks/github', {
          method: 'POST',
          body: '{}',
          headers,
        }),
        { ...env, GITHUB_WEBHOOK_SECRET: '' },
      ),
    ).rejects.toMatchObject({ code: 'invalid_secret' });
  });
});

describe('Deno example', () => {
  it('verifies and then parses a form-encoded Slack command', async () => {
    const warnings = captureWarnings();
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
    expect(bad.status).toBe(400);
    expect(warnings()).toEqual(['rejected slack request: missing_header']);
  });
});

describe('replay protection store', () => {
  it('reserves an id, then remembers it as done for the TTL', async () => {
    let now = 0;
    const store = new MemoryIdempotencyStore(() => now);
    expect(await store.reserve('evt_1', 30)).toBe('reserved');
    expect(await store.reserve('evt_1', 30)).toBe('in-progress');
    await store.complete('evt_1', 60);
    expect(await store.reserve('evt_1', 30)).toBe('done');
    now = 61_000;
    expect(await store.reserve('evt_1', 30)).toBe('reserved');
  });

  it('lets another delivery take over an expired lease, or a released one', async () => {
    let now = 0;
    const store = new MemoryIdempotencyStore(() => now);
    expect(await store.reserve('evt_1', 30)).toBe('reserved');
    now = 31_000;
    expect(await store.reserve('evt_1', 30)).toBe('reserved');
    await store.release('evt_1');
    expect(await store.reserve('evt_1', 30)).toBe('reserved');
  });

  it('sweeps expired ids at most once a minute', async () => {
    let now = 0;
    const store = new MemoryIdempotencyStore(() => now);
    for (let i = 0; i < 100; i++) {
      await store.complete(`evt_${String(i)}`, 1);
    }
    expect(await store.reserve('first', 1)).toBe('reserved'); // sweeps at t=0
    now = 30_000;
    await store.reserve('other', 1);
    expect(store.size).toBe(102); // expired, but no sweep within the minute
    now = 60_000;
    await store.reserve('last', 1);
    expect(store.size).toBe(1);
  });

  it('processOnce runs the work once, releases on failure and reports in-flight duplicates', async () => {
    const store = new MemoryIdempotencyStore(() => 0);
    const options = { leaseSeconds: 30, ttlSeconds: 60 };
    await expect(
      processOnce(store, 'evt_1', options, () => Promise.reject(new Error('boom'))),
    ).rejects.toThrow('boom');
    let release: () => void = () => undefined;
    const slow = processOnce(
      store,
      'evt_1',
      options,
      () => new Promise<void>((resolve) => (release = resolve)),
    );
    expect(await processOnce(store, 'evt_1', options, () => Promise.resolve())).toBe('in-progress');
    release();
    expect(await slow).toBe('processed');
    expect(await processOnce(store, 'evt_1', options, () => Promise.resolve())).toBe('duplicate');
  });
});
