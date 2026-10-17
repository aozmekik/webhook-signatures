/**
 * Micro-benchmark: time per successful verification, for each provider and
 * two payload sizes, plus stripe-node's own signature check for reference.
 *
 * Method: build once (`npm run build`), then for every case run a warm-up,
 * followed by SAMPLES timed batches of ITERATIONS sequential awaited calls.
 * The median batch is reported as microseconds per verification. Payloads are
 * synthetic JSON of the stated size.
 *
 * Usage: npm run build && node scripts/bench.ts
 */
import { existsSync } from 'node:fs';
import os from 'node:os';
import { performance } from 'node:perf_hooks';
import Stripe from 'stripe';

if (!existsSync(new URL('../dist/index.js', import.meta.url))) {
  console.error('dist/ is missing: run `npm run build` first.');
  process.exit(1);
}

// Resolved through the package's own "exports" (self-reference), i.e. dist/.
const lib = await import('webhook-signatures');
const testing = await import('webhook-signatures/testing');

const SAMPLES = 7;
const ITERATIONS = 2_000;
const WARMUP = 500;
const now = new Date('2026-03-14T15:09:26Z');

/** Valid JSON of exactly `bytes` bytes (ASCII). */
function syntheticPayload(bytes: number): string {
  const overhead = JSON.stringify({ id: 'evt_bench', type: 'bench', filler: '' }).length;
  return JSON.stringify({ id: 'evt_bench', type: 'bench', filler: 'x'.repeat(bytes - overhead) });
}

type Case = readonly [label: string, run: () => unknown];

async function cases(size: number): Promise<Case[]> {
  const payload = syntheticPayload(size);
  const secret = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
  const stripe = await testing.signStripe({ payload, secret, timestamp: now });
  const github = await testing.signGitHub({ payload, secret });
  const slack = await testing.signSlack({ payload, secret, timestamp: now });
  const shopify = await testing.signShopify({ payload, secret });
  const standard = await testing.signStandardWebhook({
    payload,
    secret,
    id: 'msg_1',
    timestamp: now,
  });
  const twilio = await testing.signTwilio({
    payload,
    secret,
    url: 'https://example.com/hook',
    scheme: 'body-sha256',
  });
  const paddle = await testing.signPaddle({ payload, secret, timestamp: now });
  const lemon = await testing.signLemonSqueezy({ payload, secret });
  const stripeHeader = stripe['stripe-signature'] ?? '';
  const subtle = Stripe.createSubtleCryptoProvider();
  const stripeSignature = Stripe.webhooks.signature;
  if (stripeSignature === null) {
    throw new Error('stripe-node exposes no signature helper');
  }
  const nowMs = now.getTime();
  return [
    ['verifyStripe', () => lib.verifyStripe({ payload, headers: stripe, secret, now })],
    ['verifyGitHub', () => lib.verifyGitHub({ payload, headers: github, secret })],
    ['verifySlack', () => lib.verifySlack({ payload, headers: slack, secret, now })],
    ['verifyShopify', () => lib.verifyShopify({ payload, headers: shopify, secret })],
    [
      'verifyStandardWebhook',
      () => lib.verifyStandardWebhook({ payload, headers: standard, secret, now }),
    ],
    [
      'verifyTwilio (bodySHA256)',
      () => lib.verifyTwilio({ payload, headers: twilio.headers, secret, url: twilio.url }),
    ],
    ['verifyPaddle', () => lib.verifyPaddle({ payload, headers: paddle, secret, now })],
    ['verifyLemonSqueezy', () => lib.verifyLemonSqueezy({ payload, headers: lemon, secret })],
    // Reference points: stripe-node's signature check alone (no JSON parsing),
    // with its default node:crypto provider and with its Web Crypto provider.
    [
      'stripe-node signature.verifyHeader (node:crypto, sync)',
      () => stripeSignature.verifyHeader(payload, stripeHeader, secret, 300, undefined, nowMs),
    ],
    [
      'stripe-node signature.verifyHeaderAsync (Web Crypto)',
      () => stripeSignature.verifyHeaderAsync(payload, stripeHeader, secret, 300, subtle, nowMs),
    ],
  ];
}

async function microsPerOp(run: () => unknown): Promise<number> {
  for (let i = 0; i < WARMUP; i++) {
    await run();
  }
  const samples: number[] = [];
  for (let s = 0; s < SAMPLES; s++) {
    const start = performance.now();
    for (let i = 0; i < ITERATIONS; i++) {
      await run();
    }
    samples.push(((performance.now() - start) * 1000) / ITERATIONS);
  }
  samples.sort((a, b) => a - b);
  return samples[Math.floor(SAMPLES / 2)] ?? Number.NaN;
}

const cpu = os.cpus()[0]?.model ?? 'unknown CPU';
console.log(
  `Node ${process.version}, ${cpu}, ${os.cpus().length} cores; median of ${SAMPLES} batches x ${ITERATIONS} calls\n`,
);
console.log('| Case | 1 KiB body (µs/op) | 64 KiB body (µs/op) |');
console.log('| --- | ---: | ---: |');
const small = await cases(1024);
const large = await cases(64 * 1024);
for (const [index, [label, run]] of small.entries()) {
  const largeRun = large[index]?.[1];
  if (largeRun === undefined) {
    continue;
  }
  const a = await microsPerOp(run);
  const b = await microsPerOp(largeRun);
  console.log(`| ${label} | ${a.toFixed(1)} | ${b.toFixed(1)} |`);
}
