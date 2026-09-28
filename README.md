<div align="center">

# ReallyMe OpenID4VCI

**OpenID4VCI infrastructure for issuers, wallets, and EUDI ecosystems**

[![OpenID4VCI 1.0 Final](https://img.shields.io/badge/OpenID4VCI-1.0%20Final-0f766e)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
[![HAIP 1.0 Final](https://img.shields.io/badge/HAIP-1.0%20Final-0f766e)](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
[![crates.io](https://img.shields.io/crates/v/reallyme-openid4vci.svg)](https://crates.io/crates/reallyme-openid4vci)
[![MSRV](https://img.shields.io/badge/MSRV-1.96-475569)](Cargo.toml)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](docs/SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

[Identity](https://github.com/reallyme/identity) · [SSI](https://github.com/reallyme/ssi) · **OpenID4VCI** · [OpenID4VP](https://github.com/reallyme/openid4vp) · [Wallet](https://github.com/reallyme/wallet) · [ZK](https://github.com/reallyme/zk)

</div>

`reallyme-openid4vci` provides the protocol infrastructure for issuing digital
credentials using **OpenID for Verifiable Credential Issuance 1.0
(OpenID4VCI)** and the **OpenID4VC High Assurance Interoperability Profile
(HAIP) 1.0**.

It supports both sides of the issuance exchange: issuers that authorize and
deliver credentials, and wallets that discover offers, establish authorization,
prove key possession, and receive credentials.

The protocol core is independent of HTTP frameworks, persistence, key
management, and platform SDKs. Those capabilities are supplied through explicit
interfaces, keeping the protocol core portable across server, native, and
WebAssembly environments.

> **Looking for the ReallyMe SDK?** Start with
> [ReallyMe Identity](https://github.com/reallyme/identity), the
> application-facing SDK for building issuers, wallets, and identity-enabled
> applications. This repository provides its underlying OpenID4VCI protocol
> implementation.

## Quick start

Application developers should normally use
[ReallyMe Identity](https://github.com/reallyme/identity). For direct access to
the Rust protocol stack, add the public facade:

```toml
[dependencies]
reallyme-openid4vci = "0.1"
```

The parser treats a Credential Offer as untrusted input, enforces the final
specification's structural and URL requirements, and returns a typed error on
failure:

```rust
use reallyme_openid4vci::types::{CredentialOffer, OpenId4VciResult};

fn main() -> OpenId4VciResult<()> {
    let offer = CredentialOffer::parse_json(
        r#"{
            "credential_issuer": "https://issuer.example",
            "credential_configuration_ids": ["pid"]
        }"#,
    )?;
    let _inline_offer_uri = offer.to_uri()?;
    Ok(())
}
```

Use `reallyme-openid4vci-wallet` when the application needs the wallet-side
offer, metadata, proof, request, encryption, and deferred-flow boundaries
without the complete facade.

## Capabilities

| Area | Support |
| --- | --- |
| Protocol | OpenID4VCI 1.0 Final |
| Security profile | HAIP 1.0 Final |
| Roles | Issuer and wallet |
| Flows | Wallet-initiated and issuer-initiated |
| Credential formats | SD-JWT VC and mdoc through ReallyMe SSI |
| Security | DPoP, PKCE, wallet attestation, key attestation, and encrypted credential requests and responses |
| EUDI | PID issuance policy and profile constraints |
| Platforms | Native Rust and `wasm32-unknown-unknown` |
| Interfaces | Rust APIs, protobuf operations, ProtoJSON, and optional HTTP framing |

## Architecture

This is a conceptual ownership and composition view, not a Cargo dependency
graph.

```text
                                 ReallyMe Identity
                              application-facing SDKs
                                         │
                                         ▼
┌──────────────────────┐  ┌──────────────────────────────┐
│ Host capabilities    │  │ ReallyMe OpenID4VCI          │
│ network/HTTP runtime ├─►│ issuer · wallet · profiles   │
│ storage · keys · UI  │  │ HTTP framing · protobuf      │
│ trust evidence       │  └──────────────┬───────────────┘
└──────────────────────┘                 │
                                         ▼
                                   ReallyMe SSI
                       OAuth · credentials · trust primitives
```

OpenID4VCI implements both the issuer and wallet sides of credential issuance.
ReallyMe Identity composes those protocol capabilities into the
application-facing SDK.

Shared OAuth mechanics—including PAR, DPoP, PKCE, authorization-server metadata,
and attestation-based client authentication—are provided by
[`reallyme/ssi`](https://github.com/reallyme/ssi). Credential formats, claims,
status, and trust primitives are provided by the same layer, while wallet
inventory, consent, lifecycle, persistence policy, durable issuance state, and
audit policy are owned by
[ReallyMe Wallet](https://github.com/reallyme/wallet).

The protocol core is transport-agnostic. Optional HTTP adapters own
OpenID4VCI routing and framing; the host owns the network and HTTP runtime and
injects storage, key-use, external trust-evidence acquisition, and user
interaction capabilities. The protobuf interface provides bounded binary
decoding and generated ProtoJSON; transport-level compression remains the
responsibility of the host or SDK.

The HTTP example composes a repeatable authorization-server provider for local
conformance testing. It is not a production OAuth server and is not evidence
that the library owns end-user authentication, consent, client registration,
token persistence, or deployment policy.

Platform packaging is provided by ReallyMe Identity. This repository supports
`native` and `wasm` Rust feature lanes and verifies the complete graph for
`wasm32-unknown-unknown`, but it does not publish a standalone Wasm binary or an
npm package. ReallyMe Identity composes the lower-level Rust components into
one application-facing Wasm module so handles and memory never cross separate
Wasm instances.

## Which layer should I use?

| Goal | Start here |
| --- | --- |
| Build an application with ReallyMe | Use the application-facing [ReallyMe Identity](https://github.com/reallyme/identity) SDK. |
| Own wallet state, consent, lifecycle, persistence policy, and audit policy | Use [ReallyMe Wallet](https://github.com/reallyme/wallet). |
| Validate or generate OpenID4VCI wire documents | Use `reallyme-openid4vci-types`. |
| Integrate the wallet-side protocol boundary directly | Use `reallyme-openid4vci-wallet`; application developers should normally start with ReallyMe Identity. |
| Integrate the canonical protobuf contract | Use `reallyme-openid4vci-proto`. |
| Integrate issuer behavior directly | Use `openid4vci-issuer`. |
| Select HAIP or EUDI PID policy | Use `openid4vci-profiles`. |
| Add bounded protobuf conversions | Use `openid4vci-proto-codec`. |
| Add the HTTP framing boundary | Use `openid4vci-http`. |

Released dependencies resolve from crates.io; a sibling checkout is not
required.

## Repository structure

| Path | Purpose |
| --- | --- |
| `crates/openid4vci` | Workspace facade and SDK-facing policy surface. |
| `crates/types` | Validated final-spec wire types and protocol errors. |
| `crates/issuer` | Pure issuer endpoint behavior over injected traits. |
| `crates/wallet` | Wallet-side offer and request construction. |
| `crates/attestation` | Wallet and key attestation boundaries. |
| `crates/profiles` | HAIP and EUDI PID policy. |
| `crates/proto`, `crates/proto-codec` | Canonical generated contracts, bounded codecs, and explicit domain mappings. |
| `crates/http` | Optional OpenID4VCI HTTP framing adapters. |
| `conformance`, `vectors` | OIDF harnesses, requirement evidence, protocol vectors, and negative cases. |

Concrete zero-knowledge provers and verifiers are intentionally outside this
repository. Where a ZK integration is required, the workspace depends only on
the neutral `reallyme-zk-api` boundary; issuer services remain independent of
concrete ZK implementations.

### Package availability

The crates.io publication surface contains exactly these packages:

| Package | Purpose |
| --- | --- |
| [`reallyme-openid4vci-proto`](https://crates.io/crates/reallyme-openid4vci-proto) | Canonical generated protobuf and ProtoJSON contract. |
| [`reallyme-openid4vci-types`](https://crates.io/crates/reallyme-openid4vci-types) | Validated OpenID4VCI 1.0 wire types and protocol errors. |
| [`openid4vci-attestation`](https://crates.io/crates/openid4vci-attestation) | Wallet-attestation and key-attestation models and validation. |
| [`reallyme-openid4vci-wallet`](https://crates.io/crates/reallyme-openid4vci-wallet) | Wallet-side request construction, validation, metadata resolution, proofs, and encrypted credential handling. |
| [`openid4vci-profiles`](https://crates.io/crates/openid4vci-profiles) | HAIP and EUDI PID profile policy. |
| [`openid4vci-issuer`](https://crates.io/crates/openid4vci-issuer) | Transport-independent issuer endpoint behavior. |
| [`openid4vci-proto-codec`](https://crates.io/crates/openid4vci-proto-codec) | Bounded conversions between domain and protobuf models. |
| [`openid4vci-http`](https://crates.io/crates/openid4vci-http) | Feature-gated HTTP framing adapters. |
| [`reallyme-openid4vci`](https://crates.io/crates/reallyme-openid4vci) | Feature-gated facade over the supported protocol stack. |

The release tooling rejects any additional publishable workspace crate. The
conformance harness remains repository-only and is never published.

## Conformance

The repository targets the OpenID4VCI 1.0 and HAIP 1.0 Final Specifications.
Conformance tooling exercises issuer-role profiles for SD-JWT VC and mdoc
across wallet-initiated and issuer-initiated flows. Tests are pinned to OIDF
Conformance Suite `release-v5.3.1`, commit
`440eec8bac7b12b7389d7ca9cbc459b53507a443`.

The repository retains role adapters, protocol tests, vectors, negative cases,
and revision-bound evidence. The [conformance guide](conformance/README.md)
explains the supported local checks. Passing repository tests or a local suite
run is not an OpenID Foundation certification claim.

## Documentation

| Topic | Reference |
| --- | --- |
| Trust and attacker model | [Threat model](docs/THREAT_MODEL.md) and [trust evidence profile](docs/TRUST_EVIDENCE_PROFILE.md) |
| Vulnerability reporting | [Security policy](docs/SECURITY.md) |
| Conformance testing | [Conformance guide](conformance/README.md) |
| Reusable protocol cases | [Test vectors](vectors/README.md) |

## Development

Regenerate the canonical protobuf contract through the reviewed pipeline:

```sh
scripts/regenerate-openid4vci-proto.sh
```

Published crates declare Rust 1.96 as their minimum supported Rust version.
Repository development and primary CI use the pinned Rust 1.98.1 toolchain;
CI also checks the public crate set with Rust 1.96.

Run the repository gate and the core Rust checks before submitting changes:

```sh
git clone --no-checkout https://github.com/reallyme/release-readiness.git .release-readiness
git -C .release-readiness checkout --detach bdedc88f3f25fcc14242730d4dec6ce6a0c75531
node .release-readiness/scripts/run-consumer-check.mjs
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check --workspace --no-default-features --features wasm --target wasm32-unknown-unknown
cargo deny check
```

## Security

Follow the [security policy](docs/SECURITY.md) when reporting a vulnerability.
Do not include credentials, access tokens, private keys, attestation material,
or production issuer and wallet data in reports.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

Third-party components retain their own licenses and notices.

## Copyright and Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe® is a registered trademark of ReallyMe LLC.
