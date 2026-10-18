/** Cross-validation against the verifier exported by the official Slack Bolt framework. */
import { verifySlackRequest } from '@slack/bolt';
import { describe, expect, it } from 'vitest';
import { verifySlack } from 'webhook-signatures';
import { signSlack } from 'webhook-signatures/testing';
import { NOW, expectCode } from '../support/assertions.js';

const signingSecret = '8f742231b10e8888abcd99yyyzzz85a5';
const bodies = [
  'token=gIkuvaNzQIHg97ATvDxqgjtO&team_id=T0001&command=%2Fweather&text=94070',
  JSON.stringify({ type: 'event_callback', event: { type: 'app_mention', text: 'günaydın' } }),
];

describe('@slack/bolt interop', () => {
  it.each(bodies)('verifySlackRequest accepts signSlack output (%#)', async (body) => {
    const headers = await signSlack({ payload: body, secret: signingSecret, timestamp: NOW });
    expect(() => {
      verifySlackRequest({
        signingSecret,
        body,
        headers: {
          'x-slack-signature': headers['x-slack-signature'],
          'x-slack-request-timestamp': Number(headers['x-slack-request-timestamp']),
        },
        nowMilliseconds: NOW.getTime(),
      });
    }).not.toThrow();
  });

  it('both reject a tampered body', async () => {
    const body = bodies[0] ?? '';
    const headers = await signSlack({ payload: body, secret: signingSecret, timestamp: NOW });
    const tampered = body.replace('94070', '10001');
    expect(() => {
      verifySlackRequest({
        signingSecret,
        body: tampered,
        headers: {
          'x-slack-signature': headers['x-slack-signature'],
          'x-slack-request-timestamp': Number(headers['x-slack-request-timestamp']),
        },
        nowMilliseconds: NOW.getTime(),
      });
    }).toThrow(/signature mismatch/);
    await expectCode(
      verifySlack({ payload: tampered, headers, secret: signingSecret, now: NOW }),
      'signature_mismatch',
    );
  });
});
