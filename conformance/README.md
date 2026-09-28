# OpenID4VCI Conformance Testing

This directory contains protocol vectors, OpenID Foundation Conformance Suite
adapters, and EUDI interoperability fixtures for the OpenID4VCI issuer and
wallet roles.

Repository tests validate implementation behavior. They do not by themselves
constitute an OpenID Foundation certification or an independent assessment.

## Local validation

Run the portable vectors and conformance manifest checks with:

```sh
cargo test -p openid4vci-conformance --all-features
cargo test -p openid4vci-conformance --test vectors_tests --all-features
```

The vectors cover valid and invalid OpenID4VCI messages, proof and trust
decisions, JWE interoperability, and bounded protobuf/ProtoJSON conversion.
All fixtures use synthetic values and must not contain production credentials,
tokens, operational private keys, or personal data. A fixture may contain an
explicitly documented synthetic signing key when deterministic protocol output
requires it; such keys are public test material and must never be reused.

## OIDF suite adapter

The local OIDF adapter is pinned to Conformance Suite `release-v5.3.1`, commit
`440eec8bac7b12b7389d7ca9cbc459b53507a443`. Discovery and execution reject a
different suite revision or module inventory.

The issuer adapter covers SD-JWT VC and mdoc profiles for wallet-initiated and
issuer-initiated authorization-code flows. The wallet adapter is intended for a
composed wallet implementation with real token exchange, proof generation,
credential validation, and durable storage; the recorder-only harness is not a
wallet implementation.

The example issuer is conformance infrastructure, not a deployable issuer. Its
fixed identifiers, synthetic private keys, deterministic person data, and
automatic authorization decisions exist only to make local test runs
repeatable. It does not authenticate an end user, obtain production consent,
protect keys in an HSM, or provide durable multi-tenant state. Do not expose it
to an untrusted network or reuse any fixture key or identifier.

Each public runner executes one profile selected from
`oidf/profile-matrix.json`. This keeps local and hosted OIDF self-assessment
available without embedding a product release, deployment bill of materials,
or official submission target set in this protocol repository. A composed
product orchestrator may select all supported profiles and bind their results
to its own release evidence.

Run the preflight checks before starting a local suite:

```sh
scripts/conformance/preflight_oidf_oid4vci_issuer.sh
scripts/conformance/preflight_oidf_oid4vci_wallet.sh
```

For transport integration testing, the recorder-only wallet launch harness can
be started with `scripts/conformance/serve_oidf_oid4vci_wallet_harness.sh`.
It validates and records suite launches, but it cannot satisfy composed-wallet
conformance requirements.

The complete commands require a checked-out OIDF suite and a reachable issuer
or composed wallet. Generated results are written below
`target/conformance-results/` and are intentionally not committed.

## Requirement-ledger scope

The JSON files under `requirements/` are selected implementation-evidence
ledgers for security-sensitive and interoperability-critical requirements.
They are not an exhaustive normative index of every MUST, SHOULD, and MAY in
the specifications. Each included applicable entry has an implementation owner
and executable test anchors; exclusions and broader certification scope remain
the responsibility of the composed product's conformance program.

## Directory layout

- `requirements/` maps specification requirements to executable tests.
- `oidf/` contains the pinned suite contract and supported profile matrix.
- `eudi/` contains pinned EUDI sources and interoperability descriptors.
- `fixtures/` contains synthetic runner and cross-implementation inputs.

Retained or generated result evidence is owned by
`reallyme/identity-conformance`, where it can be bound to composed-repository
revisions and reviewed for public disclosure. This protocol repository keeps
only the reusable inputs and execution mechanisms needed to reproduce those
results.

## Handling results

Treat suite exports as potentially sensitive. Review and redact them before
sharing, even when the local normalization step removes known secret fields.
Never commit bearer tokens, transaction codes, private keys, credential
plaintext, personal data, or hosted-suite credentials.

For the OpenID Foundation certification process, use the Foundation's current
[OpenID4VCI conformance guidance](https://openid.net/certification/conformance-testing-for-openid-for-verifiable-credential-issuance/).
