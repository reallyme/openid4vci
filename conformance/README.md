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

## Specification and interoperability scope

The protocol baseline is OpenID4VCI 1.0 Final and HAIP 1.0 Final, as pinned in
`specifications.lock`. OpenID4VCI 1.1 interactive authorization, credential
dataset lifecycle, and server-to-server APIs are outside this implementation's
supported protocol surface.

Metadata discovery follows the approved 1.0 Final path rules, including issuer
identifiers with a terminating slash. Retrieval URL derivation and exact issuer
identity comparison are separate operations. Authorization-server adapters own
transaction-code expiry, bounded guessing attempts, atomic invalidation, and
single-use enforcement; wire validation alone does not provide those controls.

The pinned EUDI sources and resource expectations describe comparison inputs.
They do not establish executed two-sided interoperability. This repository
contains no retained two-sided execution evidence for the pinned JVM, Swift,
PID issuer, or EUDI testing-application comparators. Local parser checks and
source inspection do not establish mTLS endpoint-alias
selection, multi-issuer grant isolation, or production platform-attestation and
provider-status enforcement. Mock platform validation and bare-JWK test inputs
do not establish hardware-backed trust.

Issuer-registration metadata is not validated against a complete Registrar
certificate profile by this protocol engine. The pinned requirement lacks the
complete field, certificate, and trust-resolution contract needed for that
validation; applications must not infer registration compliance from generic
metadata parsing.

## OIDF suite adapter

The local OIDF adapter is pinned to Conformance Suite `release-v5.3.4-36-g1e6f5433d`, commit
`1e6f5433dc61b13e484fee1dec1f0346cca0cfa5`. Discovery and execution reject a
different suite revision or module inventory.

The issuer adapter covers SD-JWT VC and mdoc profiles for wallet-initiated and
issuer-initiated authorization-code flows. The wallet adapter is intended for a
composed wallet implementation with real token exchange, proof generation,
credential validation, and durable storage; the recorder-only harness is not a
wallet implementation.

The mdoc composition uses SSI's ISO/IEC 18013-5 issuer signer, which places
`x5chain` in the unprotected `issuerAuth` header. COSE retains its generic
header-placement policy. CI runs the issuer example tests explicitly because
workspace nextest runs do not include example tests; these checks exercise the
resolved SSI dependency and reject an incompatible signer before live suite
execution.

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
```

Start the Docker-backed local suite with the repository-owned host-gateway
override. The synthetic mdoc Document Signer certificate uses
`https://localhost.emobix.co.uk:9443/security/mdoc-iaca.crl`; without this
mapping the suite container cannot reach the issuer's CRL endpoint and every
mdoc issuance reports the same `FetchMdocDsCertificateCrl` infrastructure
failure.

```sh
docker compose \
  -f /path/to/conformance-suite/docker-compose.yml \
  -f conformance/oidf/docker-compose.local-host-gateway.yml \
  up -d
```

Use the same two Compose files when stopping the suite so the project identity
and merged configuration remain explicit:

```sh
docker compose \
  -f /path/to/conformance-suite/docker-compose.yml \
  -f conformance/oidf/docker-compose.local-host-gateway.yml \
  down
```

The wallet runner performs its own fail-closed preflight after a composed
Wallet harness, source checkout, and executable have been selected.

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
