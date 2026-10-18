# ADR 0005: Configure the Twilio signature scheme per endpoint

- Status: accepted
- Date: 2026-10-18

## Context

Twilio signs `URL + name1 + value1 + name2 + value2 ...` with HMAC-SHA1: the
full request URL followed by the sorted form parameters, with no delimiters.
For JSON bodies it instead [appends a `bodySHA256` query parameter][twilio-json]
to the webhook URL and signs the URL alone; the receiver checks the body
against that hash.

For JSON and GET callbacks the verifier must use the URL as requested,
including the parameters Twilio appended, so applications build it from the
incoming request, and the query string is then under the sender's control.
twilio-node's `validateIncomingRequest` (and the first version of this
library) picked the scheme by looking for `bodySHA256` in that URL.

Combined with delimiter-free concatenation, that choice allows a forgery. An
attacker texts the victim's Twilio number a message whose body is
`&bodySHA256=<H>&x=`, where `<H>` is the SHA-256 of a JSON body they wrote.
Twilio signs the resulting form webhook for `https://example.com/sms?tenant=acme`.
If the attacker captures that signature, they can send it again with the URL
`https://example.com/sms?tenant=acmeAccountSidAC123Body&bodySHA256=<H>&x=From+15551234567`,
which is the same signed string, and their own JSON body. A verifier that
switches to JSON mode on seeing `bodySHA256` accepts it. A reviewer reported
this with a working proof of concept; `test/unit/providers.test.ts` replays it.

## Options considered

1. **Infer the scheme from the URL** (twilio-node's behaviour). Allows the
   forgery above.
2. **Rebuild the signed URL from the configured webhook URL**: append
   `bodySHA256=<hex of the body's SHA-256>` to it, so no part of the signed URL
   comes from the request. The strongest option, but it depends on details
   Twilio does not document (the separator, hex case, the configured URL's
   exact form), and it would make `url` mean different things per scheme.
3. **Configure the scheme per endpoint, and check the URL's shape in JSON
   mode.** `scheme: 'form-params'` (the default) never looks at
   `bodySHA256`; `scheme: 'body-sha256'` requires the URL to end with exactly
   one `bodySHA256` parameter and to have no fragment, which is what
   "appends" produces.

## Decision

Option 3. In form-params mode the forged request is verified as form
parameters and fails. In JSON mode the re-assembled URL is rejected because
the signed string goes on with further parameters (`&x=From...`) after the
planted hash. Hiding them in a `#fragment` fails too, since fragments are
rejected, and dropping the `&x=` delimiter leaves a hash value that matches
no body.

## Consequences

- Endpoints that receive JSON must pass `scheme: 'body-sha256'`; without it
  they fail with a `signature_mismatch` whose message names the option.
  Mixing form and JSON callbacks on one URL is not supported; separate URLs
  are recommended anyway.
- If Twilio ever placed `bodySHA256` somewhere other than the end of the
  query, JSON verification would fail closed. That contradicts its
  documentation, and the interop tests against twilio-node would show it.
- The protocol's other limits remain and are documented in the README rather
  than hidden: a valid signature covers the concatenated string, not one split
  of it into parameters, repeated identical pairs collapse, and nothing
  expires. Handlers must validate the parameters they read and be idempotent.

[twilio-json]: https://www.twilio.com/docs/usage/webhooks/webhooks-security
