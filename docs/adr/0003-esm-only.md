# ADR 0003: Ship ESM only, compiled with `tsc`

- Status: accepted
- Date: 2026-10-18

## Context

The package targets Node.js 22 and newer plus edge runtimes, all of which load
ECMAScript modules natively. Publishing both ESM and CommonJS builds is common,
but it creates the dual-package hazard: an application that ends up loading
both copies gets two distinct `WebhookVerificationError` classes, and
`error instanceof WebhookVerificationError` silently fails for errors thrown by
the other copy. Branching on that class is the documented way to handle
verification failures.

Node.js 22.12 and later can `require()` an ES module that has no top-level
`await`, which covers CommonJS callers on the supported Node versions.

## Options considered

1. **Dual ESM + CJS via tsup or tsdown.** Wider reach for old toolchains;
   brings the dual-package hazard and a bundler into the build.
2. **ESM only, built with `tsc`.** One copy of every class, output that mirrors
   the source files one to one, declaration maps back to `src/`.

## Decision

Option 2. `package.json` declares `"type": "module"`, `"sideEffects": false`
and an `exports` map with `.` and `./testing`. `tsc -p tsconfig.build.json`
emits JavaScript, declarations and source maps; `isolatedDeclarations` keeps
every exported signature explicit. `publint --strict` and
`@arethetypeswrong/cli --profile esm-only` check the result in CI.

## Consequences

- CommonJS code on Node.js 22.12+ can `require('webhook-signatures')`; on older
  runtimes it must use `import()`.
- No bundler is needed to build. Tree-shaking is left to the consumer's bundler;
  `scripts/bundle-size.ts` checks that importing one verifier does not pull in
  the others.
- Installing from GitHub runs the `prepare` script, which builds `dist/`, so
  the build output does not need to be committed.
