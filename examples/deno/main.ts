/**
 * Deno entry point. After `npm run build`, from the repository root:
 *
 *   SLACK_SIGNING_SECRET=... deno run --allow-net --allow-env --config examples/deno/deno.json examples/deno/main.ts
 */
import { createHandler } from './handler.ts';

declare const Deno: {
  serve(handler: (request: Request) => Promise<Response>): unknown;
  env: { get(name: string): string | undefined };
};

// Fail at startup rather than answering every request with an error.
const secret = Deno.env.get('SLACK_SIGNING_SECRET');
if (secret === undefined || secret === '') {
  throw new Error('Set SLACK_SIGNING_SECRET');
}
Deno.serve(createHandler(secret));
