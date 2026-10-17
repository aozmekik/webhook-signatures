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
Twilio URL) reject with `TypeError` or `RangeError`, so they surface in tests
instead of looking like a bad request.

**Fixed check order.** Options, then secrets (`invalid_secret`), then headers
(`missing_header`, `malformed_header`), then the HMAC (`signature_mismatch`),
then the clock (`timestamp_out_of_tolerance`). Verifying the signature before
the timestamp means `timestamp_out_of_tolerance` is only ever reported for a
request the provider really signed: it points at a replay or at clock skew,
never at a forgery. The cost is one HMAC for stale forged requests, which is
the same cost as any forged request.

**Symmetric windows with provider defaults.** The signed timestamp must be
within `toleranceSeconds` of `now` in either direction (inclusive). Defaults
follow each provider: 300 seconds for Stripe (its libraries' default), Slack
(five minutes, per its docs) and Standard Webhooks (the reference libraries),
and 5 seconds for Paddle (its SDK and docs). Some official libraries only
reject old timestamps; rejecting future ones as well closes the "pre-signed
far in the future" case at no cost for honest senders. `Infinity` disables the
check explicitly; `0` means "exactly now", not "disabled" (unlike stripe-node,
where 0 turns the check off).

**Signed bytes are used verbatim.** The signed string is built from the
timestamp text exactly as it appeared in the header, never from a re-serialized
number, so `t=0123` is not silently treated as `t=123`.

**Ambiguous headers are rejected.** A plain header record with two different
values for the same name (two casings, or an array) is `malformed_header`
rather than a guess.

## Consequences

- Handlers can map codes to responses and metrics without parsing strings.
- `toleranceSeconds` only exists on providers that sign a timestamp, so the
  type system prevents configuring a replay window that would not be enforced.
- Paddle's 5 second default is strict; queued or delayed verification must
  raise it explicitly, which the README calls out.
