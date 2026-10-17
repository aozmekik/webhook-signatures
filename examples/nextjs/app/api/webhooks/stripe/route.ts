/**
 * Next.js App Router route handler (app/api/webhooks/stripe/route.ts).
 *
 * Route handlers receive a standard `Request`; App Router does not parse the
 * body for you, so `request.arrayBuffer()` is the raw body. Works with both
 * the Node.js and the Edge runtime.
 */
import { WebhookVerificationError, verifyStripe } from 'webhook-signatures';

// Optional: export const runtime = 'edge';

export async function POST(request: Request): Promise<Response> {
  const payload = await request.arrayBuffer();
  try {
    await verifyStripe({
      payload,
      headers: request.headers,
      secret: process.env['STRIPE_WEBHOOK_SECRET'] ?? '',
    });
  } catch (error) {
    if (error instanceof WebhookVerificationError) {
      return Response.json({ error: error.code }, { status: 400 });
    }
    throw error;
  }
  const event = JSON.parse(new TextDecoder().decode(payload)) as { type: string };
  return Response.json({ received: true, type: event.type });
}
