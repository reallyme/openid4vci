# OpenID4VCI Test Vectors

This directory contains reusable protocol vectors shared by crate tests and the
conformance harness. Vector files belong here when they describe protocol data
or expected validation behavior without depending on a single test runner.

Conformance-suite configuration, reports, and runner-specific fixtures remain
under `conformance/`.

`openid4vci-trust-evidence.json` fixes the validation clock and policy in the
conformance runner. Its signature-verifier fixture rejects the single-byte
zero signature and accepts the nonzero fixture signature, allowing portable
claim-policy and signature-rejection outcomes without embedding private keys.
