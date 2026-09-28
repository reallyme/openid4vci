# Security Policy

`reallyme-openid4vci` is security-sensitive OpenID4VCI issuance infrastructure.
We take vulnerability reports seriously and appreciate coordinated disclosure.

## Reporting A Vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through either channel:

- GitHub private vulnerability reporting: use the **"Report a vulnerability"**
  button under this repository's **Security** tab.
- Email: **security@really.me**. For end-to-end encrypted disclosure, request
  our current PGP key in a first, contentless message; we will reply with it
  before you send details.

Please include, to the extent you can:

- the affected crate, function, and feature lane;
- the commit or version you tested;
- a minimal reproduction, input, proof, token, or failing test;
- your assessment of impact, such as signature acceptance, proof confusion,
  parser denial of service, credential validation bypass, or data leakage.

## What To Expect

- **Acknowledgement** within 3 business days.
- **Triage and initial assessment** within 10 business days, including whether
  we can reproduce.
- **Coordinated disclosure**: we aim to ship a fix and publish an advisory
  within 90 days of triage, sooner for actively exploited issues.

## Scope

In scope:

- malformed JOSE, COSE, X.509, DID, VC, or VP input that panics, exhausts
  memory, or bypasses validation;
- signature, proof, key-binding, or verification-method confusion;
- accepting unsupported algorithms or silently falling back to a different
  algorithm/provider;
- PII, credential contents, key material, or untrusted input bytes leaking
  through error variants, logs, panics, or debug output;
- parser behavior that diverges from the repository contract or applicable
  standards in a security-relevant way.

Out of scope:

- vulnerabilities in dependencies, except where this repository needs a pin,
  mitigation, or public advisory;
- issues requiring an already-compromised host, malicious build toolchain, or
  physical access;
- general hardening suggestions without a concrete exploit path.

## Supported Versions

Supported release lines are identified in GitHub releases and security
advisories. Security fixes are developed against `main`; source-based users
should pin an exact commit and watch releases and advisories for changes to the
supported versions.
