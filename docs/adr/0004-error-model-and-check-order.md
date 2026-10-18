# ADR 0004: Error codes, check order and replay windows

- Status: accepted
- Date: 2026-10-18

## Context

Callers need to tell apart "the request is not from the provider", "my
configuration is wrong" and "my clock is wrong", both to respond correctly and
to debug. Error messages are not a stable interface. Providers also document
different replay windows, and some only check one direction.

## Decision

**Two kinds of failure.** Verification failures reject with
`WebhookVerificationError`, whose `code` is one of `missing_header`,
`malformed_header`, `timestamp_out_of_tolerance`, `signature_mismatch` or
`invalid_secret`, plus `provider` and the lower-case `header` concerned.
Programmer errors (a payload that is not a string or bytes, usually because a
body parser already ran; a negative tolerance; an invalid `now`; a relative
Twilio URL; a header value that is not a string or an array of strings)
reject with `TypeError` or `RangeError`, so they surface in tests instead of
looking like a bad request.

**Fixed check order.** Types first (`TypeError` / `RangeError`: tolerance,
clock, Twilio URL and scheme, the headers object, the value of every header
the verifier reads, and the payload), then secrets (`invalid_secret`), then
header contents (`missing_header`, `malformed_header`), then the HMAC
(`signature_mismatch`), then the clock (`timestamp_out_of_tolerance`).

Every verifier gets the type and secret steps from one shared function. It
takes the names of all the headers the verifier will read, type-checks their
values before it looks at the secret, and returns the only way to read them,
typed to those names, so a verifier cannot read a header that was not checked
up front. The values of other headers are never inspected, so an unrelated
non-string value does not block verification. Content errors such as
conflicting duplicates are raised when a header is read, after the secret
check. The conformance suite checks, per provider, that a parsed body or a
non-string value in any header it reads, combined with an unusable secret,
reports the `TypeError`, which points at the actual mistake.

Verifying the signature before the timestamp means
`timestamp_out_of_tolerance` is only ever reported for a request the provider
really signed: it points at a replay or at clock skew, never at a forgery.
The cost is one HMAC for stale forged requests, which is the same cost as any
forged request.

**Windows in both directions, with provider defaults.** The signed timestamp
must be within `toleranceSeconds` of `now` (inclusive). Defaults follow each
provider: 300 seconds for Stripe (its libraries' default), Slack (five
minutes, per its docs) and Standard Webhooks (the reference libraries), and
5 seconds for Paddle (its SDK and docs).

Slack and the Standard Webhooks libraries check both directions; stripe-node
and Paddle's SDK only reject old timestamps. Rejecting timestamps from the
future as well bounds how long a request stays replayable when the
provider's clock runs ahead of the receiver's. The cost falls on honest
senders whose clock is ahead by more than the window. At 300 seconds that is
negligible. At Paddle's 5 seconds it is not: a receiver running more than
5 seconds behind Paddle would reject every genuine event the SDK accepts. So
Paddle's future side is `max(toleranceSeconds, 60)` seconds. That is enough
for ordinary drift, and a future-dated request still stays replayable for
about a minute at most.

`Infinity` disables the check explicitly. `0` means "not older than now", not
"disabled" (unlike stripe-node, where 0 turns the check off).

**Signed bytes are used verbatim.** The signed string is built from the
timestamp text exactly as it appeared in the header, never from a re-serialized
number, so `t=0123` is not silently treated as `t=123`.

**Ambiguous headers are rejected.** A plain header record with two different
values for the same name (two casings, or an array) is `malformed_header`
rather than a guess.

## Consequences

- Handlers can map codes to responses and metrics without parsing strings.
- `toleranceSeconds` only exists on the options of providers that sign a
  timestamp. A direct call with an object literal, such as
  `verifyGitHub({ ..., toleranceSeconds })`, therefore fails to compile instead
  of silently configuring a window that is never enforced. TypeScript skips
  that excess-property check for options built elsewhere. `verifyWebhook` with
  a union of providers also accepts every option any member uses (see
  `VerifyWebhookOptions`); providers without timestamps ignore those.
- Paddle's 5 second default is strict for old timestamps; queued or delayed
  verification must raise it explicitly, which the README calls out.
