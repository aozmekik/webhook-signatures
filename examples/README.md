# Examples

Each example is a small, complete handler. All of them are exercised by
[`test/examples/examples.test.ts`](../test/examples/examples.test.ts) on every
CI run, under Node.js, with requests signed by `webhook-signatures/testing`:
the Express app over a real HTTP connection, and the Hono, Next.js, Workers
and Deno handlers by calling them with a standard `Request`. They do not run
inside Next.js, workerd or Deno there; the library itself does run inside
workerd and an edge-runtime VM in [`test/isolation/`](../test/isolation/).

The rules are the same everywhere:

1. **Read the raw body first, verify, then parse.** A JSON or form parser that
   runs first changes the bytes the provider signed.
2. **Answer verification failures with a plain 400 and log `error.code`.** The
   sender learns nothing about why it was rejected.
3. **Treat `invalid_secret` and a missing secret as server errors (500).** They
   mean the deployment is misconfigured, not that the request is forged.

| Example                                                                              | Framework / runtime               | How the raw body is read                    |
| ------------------------------------------------------------------------------------ | --------------------------------- | ------------------------------------------- |
| [`hono/app.ts`](hono/app.ts)                                                         | Hono (Workers, Bun, Deno, Node)   | `await c.req.arrayBuffer()`                 |
| [`nextjs/app/api/webhooks/stripe/route.ts`](nextjs/app/api/webhooks/stripe/route.ts) | Next.js App Router (Node or Edge) | `await request.arrayBuffer()`               |
| [`express/app.ts`](express/app.ts)                                                   | Express 5                         | `express.raw({ type: 'application/json' })` |
| [`cloudflare-workers/worker.ts`](cloudflare-workers/worker.ts)                       | Cloudflare Workers                | `await request.arrayBuffer()`               |
| [`deno/handler.ts`](deno/handler.ts)                                                 | `Deno.serve`                      | `await request.arrayBuffer()`               |
| [`replay-protection/store.ts`](replay-protection/store.ts)                           | any                               | (processes each message id once)            |

## Running them locally

Inside this repository the examples import the package by name
(`webhook-signatures`), which resolves to the build output, so build first:

```sh
npm install
npm run build
```

- **Express** (Node.js 22.18 or newer strips the types):
  `GITHUB_WEBHOOK_SECRET=dev-secret node examples/express/server.ts`
- **Deno**: `examples/deno/deno.json` maps `webhook-signatures` to `../../dist/index.js`:
  `SLACK_SIGNING_SECRET=dev-secret deno run --allow-net --allow-env --config examples/deno/deno.json examples/deno/main.ts`.
  Deno is not installed in CI.
- **Cloudflare Workers**: `cd examples/cloudflare-workers && npx wrangler dev`
  (uses `wrangler.toml`; set the secrets with `.dev.vars`). Wrangler is not a
  dependency of this repository.
- **Hono**: `createApp(handleEvent)` returns the app; the module comment shows
  how to serve it on Workers, Node.js, Bun and Deno, where the secrets come
  from bindings or the `env` argument of `app.fetch`.
- **Next.js**: copy the route file into `app/api/webhooks/stripe/route.ts` of a
  Next.js project that installed this package.

In your own project, install the package (`npm install github:aozmekik/webhook-signatures`
until it is published to npm) and copy the handler you need.
