/**
 * Cross-validation against the official Paddle Node.js SDK. The SDK reads the
 * wall clock with a 5 second window, so the clock is faked.
 */
import { Paddle } from '@paddle/paddle-node-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { verifyPaddle } from 'webhook-signatures';
import { signPaddle } from 'webhook-signatures/testing';
import { NOW, expectCode, shift } from '../support/assertions.js';

const secret = 'pdl_ntfset_01gkpjp8bkm3tm53kdgkx6sms7_6h3qd3uFSi9YCD3OLYAShQI90XTI5vEI';
const payload = JSON.stringify({
  event_id: 'evt_01h8bzakzx3hm2fmen703n5q45',
  event_type: 'transaction.completed',
  occurred_at: '2026-03-14T15:09:26.000000Z',
  notification_id: 'ntf_01h8bzam1z32agrxjwhjgqk8w6',
  data: { id: 'txn_01h8bz', status: 'completed' },
});
// Constructing the client makes no network request.
const paddle = new Paddle('pdl_sdbx_apikey_placeholder_for_tests');

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('@paddle/paddle-node-sdk interop', () => {
  it('the SDK accepts signPaddle output', async () => {
    const signature =
      (await signPaddle({ payload, secret, timestamp: NOW }))['paddle-signature'] ?? '';
    expect(await paddle.webhooks.isSignatureValid(payload, secret, signature)).toBe(true);
    // Four seconds later is still inside Paddle's window.
    vi.setSystemTime(shift(NOW, 4));
    expect(await paddle.webhooks.isSignatureValid(payload, secret, signature)).toBe(true);
    await expect(
      verifyPaddle({ payload, headers: { 'paddle-signature': signature }, secret }),
    ).resolves.toEqual({ provider: 'paddle', timestamp: NOW });
  });

  it('the SDK reads the last h1, so a rotation header verifies for the newest secret', async () => {
    const rotated = await signPaddle({
      payload,
      secret: ['pdl_ntfset_old', secret],
      timestamp: NOW,
    });
    const signature = rotated['paddle-signature'] ?? '';
    expect(await paddle.webhooks.isSignatureValid(payload, secret, signature)).toBe(true);
    for (const key of ['pdl_ntfset_old', secret]) {
      await expect(
        verifyPaddle({ payload, headers: { 'paddle-signature': signature }, secret: key }),
      ).resolves.toBeDefined();
    }
  });

  it('both reject a tampered body and a wrong secret', async () => {
    const signature =
      (await signPaddle({ payload, secret, timestamp: NOW }))['paddle-signature'] ?? '';
    const tampered = payload.replace('completed', 'refunded');
    expect(await paddle.webhooks.isSignatureValid(tampered, secret, signature)).toBe(false);
    expect(await paddle.webhooks.isSignatureValid(payload, 'pdl_ntfset_other', signature)).toBe(
      false,
    );
    await expectCode(
      verifyPaddle({ payload: tampered, headers: { 'paddle-signature': signature }, secret }),
      'signature_mismatch',
    );
  });

  it('both enforce the 5 second window', async () => {
    const signature =
      (await signPaddle({ payload, secret, timestamp: shift(NOW, -6) }))['paddle-signature'] ?? '';
    expect(await paddle.webhooks.isSignatureValid(payload, secret, signature)).toBe(false);
    await expectCode(
      verifyPaddle({ payload, headers: { 'paddle-signature': signature }, secret }),
      'timestamp_out_of_tolerance',
    );
  });
});
