<div align="center">

# ReallyMe OpenID4VCI

**Feature-gated Rust facade for OpenID4VCI issuers and wallets**

[![OpenID4VCI 1.0 Final](https://img.shields.io/badge/OpenID4VCI-1.0%20Final-0f766e)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
[![HAIP 1.0 Final](https://img.shields.io/badge/HAIP-1.0%20Final-0f766e)](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
[![crates.io](https://img.shields.io/crates/v/reallyme-openid4vci.svg)](https://crates.io/crates/reallyme-openid4vci)
[![docs.rs](https://docs.rs/reallyme-openid4vci/badge.svg)](https://docs.rs/reallyme-openid4vci)
[![MSRV](https://img.shields.io/badge/MSRV-1.96-475569)](https://github.com/reallyme/openid4vci/blob/main/Cargo.toml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/reallyme/openid4vci#license)

[Identity](https://github.com/reallyme/identity) · [SSI](https://github.com/reallyme/ssi) · **OpenID4VCI** · [OpenID4VP](https://github.com/reallyme/openid4vp) · [Wallet](https://github.com/reallyme/wallet) · [ZK](https://github.com/reallyme/zk)

</div>

`reallyme-openid4vci` is the supported Rust composition surface for the
focused ReallyMe OpenID4VCI crates. It provides one versioned dependency and
one feature-selection boundary while preserving the ownership of wire types,
issuer logic, wallet logic, attestation, profiles, protobuf codecs, and HTTP
framing in their dedicated crates.

The facade contains no duplicate protocol implementation. Consumers that need
only one layer can depend on the corresponding focused crate directly.

## Quick start

```toml
[dependencies]
reallyme-openid4vci = "0.1"
```

The default feature set enables the native issuer and wallet surfaces, profile
policy, protobuf codecs, HTTP framing, and ReallyMe JOSE integration:

```rust
use reallyme_openid4vci::types::{CredentialOffer, OpenId4VciResult};

fn parse_offer(input: &str) -> OpenId4VciResult<CredentialOffer> {
    CredentialOffer::parse_json(input)
}
```

Treat all offers, metadata, authorization responses, proofs, credentials, and
protobuf messages as untrusted input. The underlying crates enforce bounded
parsing and return typed protocol errors.

## Features

| Feature | Purpose |
| --- | --- |
| `native` | Native Rust backend lane. Enabled by default. |
| `wasm` | Rust compilation lane for `wasm32-unknown-unknown`; selected by the consumer instead of `native`. |
| `profiles` | HAIP and EUDI PID policy. Enabled by default. |
| `codec` | Canonical protobuf messages and bounded domain conversions. Enabled by default. |
| `http` | Axum-based HTTP framing adapters. Enabled by default. |
| `tls` | TLS support for the HTTP adapter. |
| `reqwest` | Reqwest-backed holder HTTP integration. |
| `identity-jose` | ReallyMe JOSE-backed issuer and HTTP cryptographic adapters. Enabled by default. |

For a narrow dependency surface, disable defaults and select only the required
composition:

```toml
[dependencies]
reallyme-openid4vci = { version = "0.1", default-features = false, features = ["native", "profiles"] }
```

## Ownership boundary

This crate re-exports the stable attestation, issuer, types, and wallet
surfaces. Profile, HTTP, and generated-message SDK surfaces appear only when
their corresponding features are enabled. Platform-facing SDKs, FFI, JNI, and
the composed Wasm package remain owned by
[ReallyMe Identity](https://github.com/reallyme/identity), which ensures that
applications contain one ReallyMe Rust binary and one Wasm memory domain.

See the [repository README](https://github.com/reallyme/openid4vci) for the
architecture, threat model, validation commands, and conformance scope.
