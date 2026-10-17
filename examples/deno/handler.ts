/**
 * A Slack slash-command handler for `Deno.serve` (see main.ts). Slack sends
 * `application/x-www-form-urlencoded`; verify the raw bytes first, then parse.
 */
import { WebhookVerificationError, verifySlack } from 'webhook-signatures';

export function createHandler(signingSecret: string): (request: Request) => Promise<Response> {
  return async (request) => {
    const payload = await request.arrayBuffer();
    try {
      await verifySlack({ payload, headers: request.headers, secret: signingSecret });
    } catch (error) {
      if (error instanceof WebhookVerificationError) {
        return new Response(error.code, { status: 401 });
      }
      throw error;
    }
    const form = new URLSearchParams(new TextDecoder().decode(payload));
    return Response.json({
      response_type: 'ephemeral',
      text: `You ran ${form.get('command') ?? '?'}`,
    });
  };
}
