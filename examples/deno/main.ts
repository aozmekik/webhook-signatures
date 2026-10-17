/**
 * Deno entry point. Run with `deno run --allow-net --allow-env examples/deno/main.ts`
 * after making the package resolvable (see examples/README.md).
 */
import { createHandler } from './handler.ts';

declare const Deno: {
  serve(handler: (request: Request) => Promise<Response>): unknown;
  env: { get(name: string): string | undefined };
};

Deno.serve(createHandler(Deno.env.get('SLACK_SIGNING_SECRET') ?? ''));
