# OpenID4VCI Repository Contract

This repository owns the transport-independent OpenID4VCI protocol model,
issuer and wallet state transitions, generated protobuf contracts, bounded
codecs, optional HTTP framing, and protocol conformance fixtures.

## Public boundaries

- `reallyme-openid4vci-types` owns validated OpenID4VCI wire and domain types.
- `reallyme-openid4vci-proto` owns generated, versioned protobuf messages.
- `reallyme-openid4vci-wallet` owns wallet-side protocol construction and validation.

Released versions are distributed through crates.io and documented on docs.rs.

## Private composition boundaries

The facade, issuer engine, profile policy, protobuf codec, conformance harness,
and HTTP adapter are workspace components rather than independently supported
registry packages. Applications should compose them through the ReallyMe
Identity SDK or through an explicitly reviewed host integration.

HTTP adapters must authenticate access tokens and authorize credential,
deferred-transaction, and notification identifiers before invoking the issuer
engine. Response-encryption commitments and nonce replay protection remain
mandatory across every transport.

## Dependency direction

This protocol repository depends on the public SSI and OAuth primitives it
uses. External taxonomy and combined-conformance systems may consume this
repository's requirements and evidence maps, but this repository's build and CI
do not require those systems to be available.
