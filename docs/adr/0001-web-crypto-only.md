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
- On Node.js each Web Crypto call has a fixed cost that synchronous
  `node:crypto` does not. In [the benchmark](../benchmarks.md) a 1 KiB
  verification takes about 20 µs here, against 3.5 µs for stripe-node's
  synchronous path. At 64 KiB hashing dominates: 57 to 72 µs here, against
  78 µs for stripe-node, which hashes the body as a string. Either way it is
  tens of microseconds per webhook, small next to the network round trip that
  delivered it.
- HMAC keys are imported on every call rather than cached. It is not about
  secrecy: the secret strings already live in configuration for the whole
  process lifetime, and a non-extractable `CryptoKey` would be no worse. The
  reasons are that the verifiers stay stateless (no module-level cache keyed
  by secrets, nothing to invalidate when a secret is rotated, no state shared
  between tenants that use different secrets, no memory that grows with the
  number of secrets), and that the measured cost is small. In the
  [benchmark](../benchmarks.md), one HMAC-SHA256 verify with a fresh
  `importKey` took 15.5 µs at 1 KiB and 49.0 µs at 64 KiB, against 8.9 µs
  and 42.3 µs with a reused key: about 7 µs per call. Caching can be added
  later behind the same API if a workload shows otherwise.
