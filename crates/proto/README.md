# reallyme-openid4vci-proto

Generated Buffa protobuf messages for the versioned
`reallyme.openid4vci.v1` contract.

This crate is message-only: it contains no HTTP, Connect, provider, storage, or
domain-validation runtime. Generated sensitive owners are deterministically
hardened for Debug redaction, strict unknown-field rejection, and clear/drop
zeroization. The crate packages the source schemas and language-neutral
ProtoJSON/protobuf fixtures consumed by `reallyme/identity` platform tests.

The source workspace's `openid4vci-proto-codec` crate owns bounded decoding of
untrusted protobuf and ProtoJSON input. It is intentionally not a crates.io
package. Registry consumers must provide an equivalent bounded validation
boundary rather than decoding untrusted input directly with this message crate.

The codec exposes ProtoJSON only for a sealed allowlist of generated
`reallyme.openid4vci.v1` messages. Successful binary and ProtoJSON encodes return
zeroizing owners; runtime adapters must make any unavoidable transfer into an
HTTP, FFI, or platform-owned buffer explicit.

JSON is a generated ProtoJSON request convenience. Results remain one fully
generated protobuf response with a typed result/error outcome.

Add the crate from crates.io with:

```sh
cargo add reallyme-openid4vci-proto@0.1.0
```

Licensed under either the MIT License or the Apache License, Version 2.0.
