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

## Dependencies

The published package has no runtime dependencies: everything in
`package.json` is for development and tests, and Dependabot proposes updates
weekly. `overrides` in `package.json` lift two packages that Miniflare (used
only by the workerd isolation test) pins to versions with published security
advisories: `sharp` to `^0.35.5` and Miniflare's own `undici` to `^7.30.1`.
Remove those overrides once a Miniflare release depends on fixed versions;
`npm audit` should then still report no vulnerabilities.

## Releasing

Releases are cut from `main` by the maintainer:

1. Move the `[Unreleased]` entries in `CHANGELOG.md` under the new version and
   date, and set `version` in `package.json`.
2. Run `npm run ci` on a clean clone.
3. Create an annotated tag (`git tag -a v0.1.0 -m "v0.1.0"`) and push it with
   `git push --follow-tags`. Installs can then pin it:
   `npm install github:aozmekik/webhook-signatures#v0.1.0`.
4. Create a GitHub Release for the tag and attach the `npm pack` tarball, so
   users can install the built package without the development toolchain.
5. Once, in the repository settings: enable private vulnerability reporting,
   which the link in [SECURITY.md](SECURITY.md) relies on.

**npm name.** An unrelated package named `webhook-signatures` was published
at versions 0.1.0 and 1.0.0 in September 2025 and then unpublished. npm never
allows a name@version to be reused, so those two versions can never be
published under this name. Before the first npm release, either publish the
next free version (for example 0.2.0, and 2.0.0 as the first stable release)
or move to a scope (for example `@aozmekik/webhook-signatures`), which means
updating the imports in the README, examples, tests, `tsconfig.json` paths
and the Vitest aliases.
