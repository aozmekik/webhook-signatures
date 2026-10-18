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
| `{ verifyStripe }`                         |            5,776 |              2,430 |
| `{ verifyGitHub }`                         |            4,273 |              1,929 |
| `{ verifySlack }`                          |            5,198 |              2,252 |
| `{ verifyShopify }`                        |            4,062 |              1,837 |
| `{ verifyStandardWebhook }`                |            6,146 |              2,594 |
| `{ verifyTwilio }`                         |            5,870 |              2,620 |
| `{ verifyPaddle }`                         |            5,769 |              2,438 |
| `{ verifyLemonSqueezy }`                   |            3,865 |              1,774 |
| `{ verifyWebhook }` (all providers)        |           12,978 |              4,791 |
| `webhook-signatures/testing` (all `sign*`) |            5,718 |              2,454 |

## Verification time

Time per successful verification, measured with `npm run build && npm run bench`
([`scripts/bench.ts`](../scripts/bench.ts)). Method: every case is warmed up,
then 15 interleaved rounds run one batch of 2,000 sequential awaited calls per
case. Each cell is the fastest batch / the median batch, in microseconds per
call. The bodies are synthetic JSON of the stated size, passed as bytes the
way the README recipes pass them (`request.arrayBuffer()`, `express.raw()`).
One row passes a string instead, and stripe-node is given a `Buffer`, which is
what `express.raw()` produces. The benchmark was run three times on the
final code; the table is the run with the lowest load (1-minute load average
6.7 at the start, 7.2 at the end). The other two runs, at loads between 8 and
23, were slower in every row, including the raw Web Crypto reference rows.
The fastest batches are the more stable comparison.

| Case                                                       | 1 KiB body (µs) | 64 KiB body (µs) |
| ---------------------------------------------------------- | --------------: | ---------------: |
| `verifyStripe`                                             |     22.7 / 25.6 |      66.7 / 80.9 |
| `verifyGitHub`                                             |     21.6 / 23.5 |      58.9 / 65.7 |
| `verifySlack`                                              |     22.7 / 24.9 |      67.0 / 81.4 |
| `verifyShopify`                                            |     20.8 / 22.9 |      55.8 / 65.4 |
| `verifyStandardWebhook`                                    |     23.0 / 26.0 |      68.7 / 79.7 |
| `verifyTwilio` (`bodySHA256`)                              |     35.5 / 39.0 |      71.3 / 92.5 |
| `verifyPaddle`                                             |     22.8 / 24.1 |      69.3 / 78.7 |
| `verifyLemonSqueezy`                                       |     21.0 / 22.7 |      58.0 / 67.5 |
| `verifyGitHub`, string payload                             |     22.8 / 23.8 |    148.7 / 158.5 |
| stripe-node `signature.verifyHeader` (`node:crypto`, sync) |       3.7 / 3.9 |      83.6 / 87.0 |
| stripe-node `signature.verifyHeaderAsync` (Web Crypto)     |     22.2 / 23.8 |    154.0 / 161.7 |
| Web Crypto HMAC-SHA256 verify, key imported per call       |     17.0 / 18.6 |      52.3 / 56.7 |
| Web Crypto HMAC-SHA256 verify, `CryptoKey` reused          |      9.7 / 11.3 |      45.0 / 48.1 |

How to read it:

- **Small bodies:** the fixed cost of each Web Crypto call dominates. That is
  about 21 to 23 µs per verification, against 3.7 µs for stripe-node's
  synchronous `node:crypto` path; stripe-node's own Web Crypto path costs the
  same as this library.
- **Large bodies:** hashing dominates. Given bytes, the verifiers took 56 to
  71 µs at 64 KiB. stripe-node decodes the body to a string and hashes that,
  which costs it 84 µs synchronously and 154 µs through Web Crypto.
- **Pass bytes, not strings.** With a string payload the library must UTF-8
  encode it first, and at 64 KiB that more than doubles the time (58.9 to
  148.7 µs for `verifyGitHub`). Read the body with `request.arrayBuffer()`,
  not `request.text()`.
- **Twilio** costs about 14 µs more at 1 KiB, because it also hashes the body
  with SHA-256 and parses the URL.
- **Key import:** importing the HMAC key on every call, as the verifiers do,
  adds about 7 µs (17.0 against 9.7 µs at 1 KiB, 52.3 against 45.0 µs at
  64 KiB). [ADR 0001](adr/0001-web-crypto-only.md) explains why keys are not
  cached anyway.

In every case the cost is well under a millisecond per webhook. It is a
micro-benchmark of verification alone, on Node.js only; edge runtimes were
not measured.
