# Contributing

Thanks for helping. Bug reports with a failing payload/header/secret triple
are the most useful thing you can send; for security issues follow
[SECURITY.md](SECURITY.md) instead.

## Setup

Development requires Node.js 22.18 or newer (the files in `scripts/` and the
runnable examples are TypeScript executed by Node's built-in type stripping)
and npm. The published package itself supports Node.js 22 and newer.

```sh
git clone https://github.com/aozmekik/webhook-signatures.git
cd webhook-signatures
npm ci
```

## Commands

| Command                 | What it does                                                           |
| ----------------------- | ---------------------------------------------------------------------- |
| `npm run format:check`  | Prettier, check only (`npm run format` to write)                       |
| `npm run lint`          | ESLint with typescript-eslint `strict-type-checked`, zero warnings     |
| `npm run typecheck`     | `tsc --noEmit` over src, tests, scripts and examples                   |
| `npm test`              | Every Vitest project: Node, then the unit suites in edge-runtime       |
| `npm run test:coverage` | Node project with V8 coverage; fails below 100% for `src/`             |
| `npm run test:edge`     | Unit and property suites under the `edge-runtime` environment only     |
| `npm run test:examples` | The example handlers in `examples/`, end to end                        |
| `npm run build`         | `tsc` build of `src/` into `dist/` (ESM + `.d.ts`)                     |
| `npm run check:package` | `publint --strict` and `attw --profile esm-only` on the packed tarball |
| `npm run size`          | Per-provider minified + gzipped bundle sizes (needs `npm run build`)   |
| `npm run bench`         | Verification micro-benchmark (needs `npm run build`)                   |
| `npm run ci`            | Everything CI runs, in order                                           |

## Ground rules

- `src/` uses Web-standard APIs only. No `node:*` imports, no `Buffer` or
  `process`; lint, the build and the isolation tests all enforce this.
- Implement provider behaviour from the provider's official documentation and
  cite the URL in the module comment. Where the documentation is silent and
  you follow an official SDK instead, say so in a comment.
- Every behaviour change comes with tests. New providers get an adapter in
  `test/support/providers.ts` (which enrolls them in the shared conformance and
  property suites), malformed-header cases, documented test vectors if the
  provider publishes any, and a cross-check against the official SDK when one
  exists.
- Keep `src/` at 100% statement, branch, function and line coverage.
- Tests must not depend on the wall clock: pass `now`, or use fake timers for
  third-party code that reads `Date.now()`.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).
