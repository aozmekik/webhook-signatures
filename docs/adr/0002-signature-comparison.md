# ADR 0002: Compare signatures with `crypto.subtle.verify`, over a bounded candidate list

- Status: accepted
- Date: 2026-10-18

## Context

An HMAC check must not leak, through timing, how many leading bytes of a
forged tag were correct. Several schemes also carry more than one candidate
signature per request: Stripe sends one `v1` per active secret while a secret
is rolled, Standard Webhooks sends a space-separated list, Paddle sends several
`h1` values during rotation. Users may additionally configure several secrets
of their own during a rotation.

Each candidate check costs one HMAC over the full body. If the number of
candidates were unbounded, a single request with a header listing hundreds of
signatures would cost hundreds of hash computations over a large body.

## Options considered

1. **Compute the HMAC once with `subtle.sign`, compare with a hand-written
   XOR-accumulate loop.** One HMAC per secret, but constant-time behaviour then
   rests on what the JavaScript JIT does with the loop.
2. **Compute once, then compare with a randomized double HMAC** (HMAC both tags
   under a fresh random key and compare the results). Removes the timing
   concern, at the price of an unusual construction reviewers need to check.
3. **Call `subtle.verify` for every (secret, candidate) pair.** The platform
   compares tags in native code; nothing timing-sensitive is written in
   JavaScript. Costs one HMAC per pair.

## Decision

Option 3, with a cap: a header may carry at most
`MAX_SIGNATURES_PER_HEADER = 10` candidates of the scheme being checked.
A header above the cap is rejected as `malformed_header` rather than truncated,
so a legitimate signature can never be silently ignored. Candidates of other
schemes (Stripe `v0`, Standard Webhooks `v1a`) are skipped and not counted.

Signatures must decode to exactly the length the algorithm produces
(32 bytes for HMAC-SHA256, 20 for HMAC-SHA1); anything else is
`malformed_header`. The loop stops at the first match; which pair matched is
not secret.

## Consequences

- Work per request is bounded by `secrets x 10` HMACs. In practice it is one or
  two.
- No custom constant-time code exists in the library.
- Twilio's port fallback (the URL is tried with and without its port) doubles
  the HMACs for Twilio only; those messages are a URL plus form parameters, not
  a large body.
- Ten is a judgement call: providers send one signature per active secret, and
  rotations overlap two secrets for a bounded time. If a provider is found to
  send more, the constant can be raised without changing the API.
