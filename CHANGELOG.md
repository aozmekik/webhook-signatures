# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until 1.0.0, minor versions may contain breaking changes.

## [Unreleased]

## [0.1.0] - 2026-10-18

### Added

- Verifiers built on the Web Crypto API only: `verifyStripe`, `verifyGitHub`,
  `verifySlack`, `verifyShopify`, `verifyStandardWebhook` (Svix, Resend,
  Clerk), `verifyTwilio` (form parameters and `bodySHA256` JSON bodies),
  `verifyPaddle` and `verifyLemonSqueezy`.
- `verifyWebhook(provider, options)` dispatcher with per-provider option and
  result types.
- `WebhookVerificationError` with stable codes: `missing_header`,
  `malformed_header`, `timestamp_out_of_tolerance`, `signature_mismatch`,
  `invalid_secret`.
- Symmetric replay windows with provider defaults (300 s; 5 s for Paddle) and
  an injectable clock.
- Secret rotation: lists of secrets and multi-signature headers, capped at 10
  candidate signatures per header.
- `webhook-signatures/testing` with a `sign*` helper per provider.
- Raw-body recipes for Hono, Next.js route handlers, Express, Cloudflare
  Workers and `Deno.serve`, plus a replay-protection store example.

[Unreleased]: https://github.com/aozmekik/webhook-signatures/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/aozmekik/webhook-signatures/releases/tag/v0.1.0
