/**
 * Express: mount `express.raw()` on the webhook route so `req.body` is the
 * raw `Buffer`, and register it *before* any global `express.json()`.
 *
 *   npm run build && GITHUB_WEBHOOK_SECRET=... node examples/express/server.ts
 */
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import { WebhookVerificationError, verifyGitHub } from 'webhook-signatures';

export function createApp(secret: string): express.Express {
  const app = express();

  app.post(
    '/webhooks/github',
    express.raw({ type: 'application/json', limit: '1mb' }),
    // Express 5 forwards a rejected promise to the error handler below.
    async (req: Request, res: Response) => {
      // req.headers is Node's IncomingHttpHeaders: a plain, lower-cased record.
      const { event, deliveryId } = await verifyGitHub({
        payload: req.body as Buffer,
        headers: req.headers,
        secret,
      });
      const body = JSON.parse((req.body as Buffer).toString('utf8')) as { action?: string };
      res.json({ received: true, event, deliveryId, action: body.action });
    },
  );

  // JSON parsing for every other route comes after the webhook route.
  app.use(express.json());

  app.use((error: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (error instanceof WebhookVerificationError) {
      res.status(400).json({ error: error.code });
      return;
    }
    next(error);
  });

  return app;
}
