# OpenID4VCI Repository Contract

This repository owns the transport-independent OpenID4VCI protocol model,
issuer and wallet state transitions, generated protobuf contracts, bounded
codecs, optional HTTP framing, and protocol conformance fixtures.

## Public boundaries

- `reallyme-openid4vci-types` owns validated OpenID4VCI wire and domain types.
- `reallyme-openid4vci-proto` owns generated, versioned protobuf messages.
- `openid4vci-attestation` owns wallet- and key-attestation models and validation.
- `reallyme-openid4vci-wallet` owns wallet-side protocol construction and validation.
- `openid4vci-profiles` owns HAIP and EUDI PID profile policy.
- `openid4vci-issuer` owns transport-independent issuer endpoint behavior.
- `openid4vci-proto-codec` owns bounded domain/protobuf conversion.
- `openid4vci-http` owns optional HTTP framing adapters.
- `reallyme-openid4vci` owns the thin, feature-gated Rust composition surface.

Released versions are distributed through crates.io and documented on docs.rs.

## Private composition boundaries

The conformance harness and repository policy tooling are not registry
packages. Platform SDKs, FFI, JNI, and the composed Wasm package remain in
ReallyMe Identity rather than this protocol repository.

HTTP adapters must authenticate access tokens and authorize credential,
deferred-transaction, and notification identifiers before invoking the issuer
engine. Response-encryption commitments and nonce replay protection remain
mandatory across every transport.

## Dependency direction

This protocol repository depends on the public SSI and OAuth primitives it
uses. External taxonomy and combined-conformance systems may consume this
repository's requirements and evidence maps, but this repository's build and CI
do not require those systems to be available.
