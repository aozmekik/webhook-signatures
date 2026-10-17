/**
 * A self-contained scenario that is bundled together with the library and
 * executed inside foreign runtimes (an @edge-runtime/vm context and workerd).
 * It must only use Web APIs.
 */
import {
  WebhookVerificationError,
  verifyGitHub,
  verifyLemonSqueezy,
  verifyPaddle,
  verifyShopify,
  verifySlack,
  verifyStandardWebhook,
  verifyStripe,
  verifyTwilio,
} from '../../src/index.js';
import type { HeadersInput } from '../../src/index.js';
import {
  signGitHub,
  signLemonSqueezy,
  signPaddle,
  signShopify,
  signSlack,
  signStandardWebhook,
  signStripe,
  signTwilio,
} from '../../src/testing.js';

export interface ScenarioReport {
  readonly globals: Record<string, string>;
  readonly results: Record<string, { readonly provider: string; readonly rejected: string }>;
}

interface Case {
  readonly id: string;
  readonly secret: string;
  sign(payload: Uint8Array, secret: string, now: Date): Promise<Record<string, string>>;
  verify(
    payload: Uint8Array,
    headers: HeadersInput,
    secret: string,
    now: Date,
  ): Promise<{ provider: string }>;
}

const URL_BASE = 'https://example.com/hook';
const ORIGINAL = JSON.stringify({ hello: 'edge', note: 'çağ' });

async function bodyHash(payload: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', payload));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

const cases: readonly Case[] = [
  {
    id: 'stripe',
    secret: 'whsec_edge',
    sign: (payload, secret, timestamp) => signStripe({ payload, secret, timestamp }),
    verify: (payload, headers, secret, now) => verifyStripe({ payload, headers, secret, now }),
  },
  {
    id: 'github',
    secret: 'gh',
    sign: (payload, secret) => signGitHub({ payload, secret }),
    verify: (payload, headers, secret) => verifyGitHub({ payload, headers, secret }),
  },
  {
    id: 'slack',
    secret: 'slack',
    sign: (payload, secret, timestamp) => signSlack({ payload, secret, timestamp }),
    verify: (payload, headers, secret, now) => verifySlack({ payload, headers, secret, now }),
  },
  {
    id: 'shopify',
    secret: 'shopify',
    sign: (payload, secret) => signShopify({ payload, secret }),
    verify: (payload, headers, secret) => verifyShopify({ payload, headers, secret }),
  },
  {
    id: 'standard-webhooks',
    secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
    sign: (payload, secret, timestamp) =>
      signStandardWebhook({ payload, secret, timestamp, id: 'msg_1' }),
    verify: (payload, headers, secret, now) =>
      verifyStandardWebhook({ payload, headers, secret, now }),
  },
  {
    id: 'twilio',
    secret: 'token',
    sign: async (payload, secret) =>
      (await signTwilio({ payload, secret, url: URL_BASE, scheme: 'body-sha256' })).headers,
    // The URL Twilio would call carries the hash of the *original* body.
    verify: async (payload, headers, secret) => {
      const original = new TextEncoder().encode(ORIGINAL);
      const url = `${URL_BASE}?bodySHA256=${await bodyHash(original)}`;
      return verifyTwilio({ payload, headers, secret, url });
    },
  },
  {
    id: 'paddle',
    secret: 'pdl_ntfset_edge',
    sign: (payload, secret, timestamp) => signPaddle({ payload, secret, timestamp }),
    verify: (payload, headers, secret, now) => verifyPaddle({ payload, headers, secret, now }),
  },
  {
    id: 'lemon-squeezy',
    secret: 'lemon',
    sign: (payload, secret) => signLemonSqueezy({ payload, secret }),
    verify: (payload, headers, secret) => verifyLemonSqueezy({ payload, headers, secret }),
  },
];

/** Signs, verifies (via a Headers object) and tampers with a body for every provider. */
export async function runScenario(): Promise<ScenarioReport> {
  const now = new Date('2026-03-14T15:09:26Z');
  const payload = new TextEncoder().encode(ORIGINAL);
  const tampered = new TextEncoder().encode(ORIGINAL.replace('edge', 'edgf'));
  const results: Record<string, { provider: string; rejected: string }> = {};
  for (const c of cases) {
    const headers = await c.sign(payload, c.secret, now);
    const verified = await c.verify(payload, new Headers(headers), c.secret, now);
    let rejected = 'accepted';
    try {
      await c.verify(tampered, headers, c.secret, now);
    } catch (error) {
      rejected = error instanceof WebhookVerificationError ? error.code : String(error);
    }
    results[c.id] = { provider: verified.provider, rejected };
  }
  const scope = globalThis as Record<string, unknown>;
  return {
    globals: {
      process: typeof scope['process'],
      Buffer: typeof scope['Buffer'],
      require: typeof scope['require'],
    },
    results,
  };
}
