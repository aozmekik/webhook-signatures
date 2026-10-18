/**
 * Next.js App Router route handler (app/api/webhooks/stripe/route.ts).
 *
 * Route handlers receive a standard `Request`; App Router does not parse the
 * body for you, so `request.arrayBuffer()` is the raw body. Works with both
 * the Node.js and the Edge runtime.
 */
import { WebhookVerificationError, verifyStripe } from 'webhook-signatures';

// Optional: export const runtime = 'edge';

// Read when a request arrives rather than at module load, so that building
// the app does not need the secret. A missing secret is a deployment error:
// throwing makes it a 500 instead of a stream of 400s that look like forgeries.
function stripeWebhookSecret(): string {
  const secret = process.env['STRIPE_WEBHOOK_SECRET'];
  if (secret === undefined || secret === '') {
    throw new Error('STRIPE_WEBHOOK_SECRET is not set');
  }
  return secret;
}

export async function POST(request: Request): Promise<Response> {
  const secret = stripeWebhookSecret();
  const payload = await request.arrayBuffer();
  try {
    await verifyStripe({ payload, headers: request.headers, secret });
  } catch (error) {
    // invalid_secret is a configuration error as well: let it become a 500.
    if (error instanceof WebhookVerificationError && error.code !== 'invalid_secret') {
      console.warn(`rejected stripe webhook: ${error.code}`);
      return new Response('invalid webhook', { status: 400 });
    }
    throw error;
  }
  const event = JSON.parse(new TextDecoder().decode(payload)) as { type: string };
  return Response.json({ received: true, type: event.type });
}
