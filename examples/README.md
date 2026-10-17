# Examples

Each example is a small, complete handler. All of them are executed by
[`test/examples/examples.test.ts`](../test/examples/examples.test.ts) on every
CI run, with requests signed by `webhook-signatures/testing`.

The rule is the same everywhere: **read the raw body first, verify, then
parse.** A JSON or form parser that runs first changes the bytes the provider
signed.

| Example                                                                              | Framework / runtime               | How the raw body is read                    |
| ------------------------------------------------------------------------------------ | --------------------------------- | ------------------------------------------- |
| [`hono/app.ts`](hono/app.ts)                                                         | Hono (Workers, Bun, Deno, Node)   | `await c.req.arrayBuffer()`                 |
| [`nextjs/app/api/webhooks/stripe/route.ts`](nextjs/app/api/webhooks/stripe/route.ts) | Next.js App Router (Node or Edge) | `await request.arrayBuffer()`               |
| [`express/app.ts`](express/app.ts)                                                   | Express 5                         | `express.raw({ type: 'application/json' })` |
| [`cloudflare-workers/worker.ts`](cloudflare-workers/worker.ts)                       | Cloudflare Workers                | `await request.arrayBuffer()`               |
| [`deno/handler.ts`](deno/handler.ts)                                                 | `Deno.serve`                      | `await request.arrayBuffer()`               |
| [`replay-protection/store.ts`](replay-protection/store.ts)                           | any                               | (stores processed message ids)              |

## Running them locally

Inside this repository the examples import the package by name
(`webhook-signatures`), which resolves to the build output:

```sh
npm install
npm run build
GITHUB_WEBHOOK_SECRET=dev-secret node examples/express/server.ts   # Node >= 22.18 strips types natively
```

- **Deno**: `examples/deno/deno.json` maps `webhook-signatures` to `../../dist/index.js`;
  after `npm run build`, run `deno run --allow-net --allow-env --config examples/deno/deno.json examples/deno/main.ts`.
  Deno is not installed in CI; the handler itself is exercised by the test suite.
- **Cloudflare Workers**: `examples/cloudflare-workers/wrangler.toml` is provided for
  `wrangler dev`. Wrangler is not a dependency of this repository; the worker's
  `fetch` is exercised by the test suite, and the library itself runs inside
  workerd in [`test/isolation/workerd.test.ts`](../test/isolation/workerd.test.ts).
- **Next.js**: copy the route file into `app/api/webhooks/stripe/route.ts` of a
  Next.js project that installed this package.

In your own project, install the package (`npm install github:aozmekik/webhook-signatures`
until it is published to npm) and copy the handler you need.
