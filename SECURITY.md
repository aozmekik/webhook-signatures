# Security policy

`webhook-signatures` is security-relevant code: a bug can let forged webhooks
through. Reports are welcome and taken seriously.

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's security
advisories:
[github.com/aozmekik/webhook-signatures/security/advisories/new](https://github.com/aozmekik/webhook-signatures/security/advisories/new).

Do not open a public issue for a suspected vulnerability. Include, if you can:

- the provider and the function involved;
- a minimal payload, header set and secret that reproduce the problem (use
  test secrets, never production ones);
- what you expected and what happened.

The maintainer aims to acknowledge reports within a week. Fixes are released as soon as
they are ready, and the advisory credits the reporter unless they prefer
otherwise.

## Supported versions

The project is at 0.x: only the latest release receives fixes.

## Scope

In scope: signature or timestamp checks that accept a request they should
reject, timing side channels in comparisons, crashes or unbounded work caused
by crafted headers or bodies, and documentation that leads to insecure use.

Out of scope: weaknesses in a provider's own signing scheme (for example, that
GitHub signs no timestamp), and applications that do not store message ids for
replay protection (see the README).
