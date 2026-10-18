# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until 1.0.0, minor versions may contain breaking changes.

## [Unreleased]

## [0.1.0] - 2026-10-18

First release, from GitHub only; not published to npm.

### Added

- Verifiers built on the Web Crypto API only: `verifyStripe`, `verifyGitHub`,
  `verifySlack`, `verifyShopify`, `verifyStandardWebhook` (Svix, Resend,
  Clerk), `verifyTwilio` (form parameters and `bodySHA256` JSON bodies),
  `verifyPaddle` and `verifyLemonSqueezy`.
- `verifyWebhook(provider, options)` dispatcher with per-provider option and
  result types; with a union of providers, the options must suit all of them.
- `WebhookVerificationError` with stable codes: `missing_header`,
  `malformed_header`, `timestamp_out_of_tolerance`, `signature_mismatch`,
  `invalid_secret`. Programmer errors (a payload that is not raw bytes,
  headers or a read header value of the wrong type, invalid options) are
  `TypeError` / `RangeError` and are reported before secret errors.
- Replay windows checked in both directions with provider defaults (300 s;
  for Paddle 5 s for old timestamps and at least 60 s for clock skew ahead of
  now) and an injectable clock.
- Twilio `scheme` option (`form-params` by default, or `body-sha256`), set
  per endpoint and never inferred from the URL (ADR 0005).
- Secret rotation: lists of secrets and multi-signature headers, capped at 10
  candidate signatures per header.
- Header parsing in linear time, with tests that a megabyte of padding is
  rejected quickly.
- `webhook-signatures/testing` with a `sign*` helper per provider, returning
  literal-keyed header types.
- Raw-body recipes for Hono, Next.js route handlers, Express, Cloudflare
  Workers and `Deno.serve`, plus a two-phase (reserve, then complete or
  release) replay-protection store.

[Unreleased]: https://github.com/aozmekik/webhook-signatures/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/aozmekik/webhook-signatures/releases/tag/v0.1.0
