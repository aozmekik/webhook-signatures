# Benchmarks and bundle size

Every number on this page comes from the command shown, run on 2026-10-18 on
an Apple M1 Pro (8 cores, 16 GB), macOS 26.6.2, Node v22.22.3. The machine was
shared with other jobs while measuring, so expect noise. The load average is
reported next to each run.

## Bundle size

What each import adds to a user's bundle, measured with
`npm run build && npm run size`: esbuild 0.28.2, minified ESM,
`platform: neutral`, gzip level 9 via `node:zlib`. The script also fails CI if
a single-provider bundle contains another provider's code, which would mean
tree-shaking broke.

| Import                                     | Minified (bytes) | Min + gzip (bytes) |
| ------------------------------------------ | ---------------: | -----------------: |
| `{ verifyStripe }`                         |            5,901 |              2,425 |
| `{ verifyGitHub }`                         |            4,280 |              1,881 |
| `{ verifySlack }`                          |            5,317 |              2,251 |
| `{ verifyShopify }`                        |            4,187 |              1,819 |
| `{ verifyStandardWebhook }`                |            6,180 |              2,555 |
| `{ verifyTwilio }`                         |            5,995 |              2,609 |
| `{ verifyPaddle }`                         |            5,894 |              2,436 |
| `{ verifyLemonSqueezy }`                   |            3,988 |              1,767 |
| `{ verifyWebhook }` (all providers)        |           12,896 |              4,694 |
| `webhook-signatures/testing` (all `sign*`) |            5,714 |              2,453 |

## Verification time

Time per successful verification, measured with `npm run build && npm run bench`
([`scripts/bench.ts`](../scripts/bench.ts)). Method: every case is warmed up,
then 15 interleaved rounds run one batch of 2,000 sequential awaited calls per
case. Each cell is the fastest batch / the median batch, in microseconds per
call. The bodies are synthetic JSON of the stated size, passed as bytes the
way the README recipes pass them (`request.arrayBuffer()`, `express.raw()`).
One row passes a string instead, and stripe-node is given a `Buffer`, which is
what `express.raw()` produces. The 1-minute load average was 11.7 at the start
and 8.4 at the end; the fastest batches are the more stable comparison.

| Case                                                       | 1 KiB body (µs) | 64 KiB body (µs) |
| ---------------------------------------------------------- | --------------: | ---------------: |
| `verifyStripe`                                             |     20.7 / 22.9 |      66.1 / 69.0 |
| `verifyGitHub`                                             |     19.0 / 20.0 |      57.5 / 59.0 |
| `verifySlack`                                              |     20.2 / 20.8 |      67.7 / 69.5 |
| `verifyShopify`                                            |     18.5 / 19.0 |      56.7 / 58.6 |
| `verifyStandardWebhook`                                    |     20.3 / 21.3 |      67.7 / 70.2 |
| `verifyTwilio` (`bodySHA256`)                              |     31.6 / 34.5 |      71.7 / 75.1 |
| `verifyPaddle`                                             |     20.6 / 21.6 |      68.0 / 69.7 |
| `verifyLemonSqueezy`                                       |     19.0 / 20.2 |      57.5 / 59.4 |
| `verifyGitHub`, string payload                             |     20.1 / 20.7 |    139.7 / 141.6 |
| stripe-node `signature.verifyHeader` (`node:crypto`, sync) |       3.5 / 3.7 |      78.4 / 82.2 |
| stripe-node `signature.verifyHeaderAsync` (Web Crypto)     |     20.4 / 21.3 |    143.6 / 146.7 |
| Web Crypto HMAC-SHA256 verify, key imported per call       |     15.5 / 16.1 |      49.0 / 50.6 |
| Web Crypto HMAC-SHA256 verify, `CryptoKey` reused          |       8.9 / 9.2 |      42.3 / 43.5 |

How to read it:

- **Small bodies:** the fixed cost of each Web Crypto call dominates. That is
  about 20 µs per verification, against 3.5 µs for stripe-node's synchronous
  `node:crypto` path; stripe-node's own Web Crypto path costs the same as this
  library.
- **Large bodies:** hashing dominates. Given bytes, the verifiers took 57 to
  72 µs at 64 KiB. stripe-node decodes the body to a string and hashes that,
  which costs it 78 µs synchronously and 144 µs through Web Crypto.
- **Pass bytes, not strings.** With a string payload the library must UTF-8
  encode it first, and at 64 KiB that more than doubles the time (57.5 to
  139.7 µs for `verifyGitHub`). Read the body with `request.arrayBuffer()`,
  not `request.text()`.
- **Twilio** costs about 12 µs more at 1 KiB, because it also hashes the body
  with SHA-256 and parses the URL.
- **Key import:** importing the HMAC key on every call, as the verifiers do,
  adds about 7 µs (15.5 against 8.9 µs at 1 KiB, 49.0 against 42.3 µs at
  64 KiB). [ADR 0001](adr/0001-web-crypto-only.md) explains why keys are not
  cached anyway.

In every case the cost is well under a millisecond per webhook. It is a
micro-benchmark of verification alone, on Node.js only; edge runtimes were
not measured.
