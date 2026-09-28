# OpenID4VCI v1 ProtoJSON Golden Fixtures

These documents freeze the canonical Buffa ProtoJSON spelling for the
cross-language OpenID4VCI v1 contract. Values are synthetic and contain no live
credentials, proofs, nonces, transaction identifiers, or personal data.

Every fixture must decode through the bounded production ProtoJSON codec,
round-trip byte-for-byte through protobuf binary encoding, re-encode to the
same JSON data model, and cross into its validated Rust domain type.

The matching lowercase hexadecimal protobuf wire bytes live in the sibling
`../protobuf` directory. Changing either representation requires updating both
and passing the exact parity tests.
