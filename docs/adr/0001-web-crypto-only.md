# ADR 0001: Use only the Web Crypto API and other Web-standard globals

- Status: accepted
- Date: 2026-10-18

## Context

Webhook receivers increasingly run outside Node.js: Cloudflare Workers, Vercel
and Next.js Edge functions, Deno Deploy, Bun. The official provider SDKs
mostly assume Node (`node:crypto`, `Buffer`) and some pull in large dependency
trees just to compute one HMAC. A library that verifies signatures for several
providers should run unchanged on all of these runtimes and add nothing to a
deployment beyond its own code.

Every target runtime implements the same small set of Web APIs:
`crypto.subtle` (HMAC with SHA-1 and SHA-256, SHA-256 digests),
`TextEncoder`/`TextDecoder`, `atob`/`btoa`, `URL`/`URLSearchParams` and
`Headers`.

## Options considered

1. **`node:crypto`, with polyfills for other runtimes.** Fast and synchronous
   on Node, but Workers only offer it behind `nodejs_compat`, and polyfills
   are large and drift from the real module.
2. **Conditional exports**: `node:crypto` on Node, Web Crypto elsewhere. Two
   implementations to test and keep equivalent; the fast path only helps Node.
3. **A bundled pure-JavaScript SHA-256/HMAC.** Synchronous everywhere, but it
   means shipping and auditing hand-written cryptography, with no
   constant-time guarantees from the platform.
4. **Web Crypto only.** One implementation; cryptography and tag comparison
   are done by the platform.

## Decision

Option 4. `src/` may use only Web-standard globals. This is enforced three
ways:

- `tsconfig.build.json` compiles `src/` against the `WebWorker` library with no
  `@types/node`, so `Buffer` or `process` do not type-check;
- ESLint bans Node built-in imports and Node globals in `src/`;
- the test suite bundles `src/` for esbuild's `neutral` platform (where
  `node:*` cannot resolve) and runs it inside an `@edge-runtime/vm` context and
  inside workerd, neither of which has `process`, `Buffer` or `require`.

## Consequences

- Every `verify*` and `sign*` function is `async`, because `crypto.subtle` is.
- Zero runtime dependencies.
- On Node.js, Web Crypto is slower per call than synchronous `node:crypto`
  (the README benchmark shows the gap, and that stripe-node's own Web Crypto
  path costs about the same as this library). The absolute cost is tens of
  microseconds per webhook, which is small next to the network round trip that
  delivered it.
- HMAC keys are imported on every call; caching `CryptoKey`s would need a
  cache keyed by secret strings, which would keep secrets reachable in memory
  for longer than a request.
