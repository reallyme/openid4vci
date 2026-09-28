# reallyme-openid4vci-types

Validated, transport-independent OpenID4VCI 1.0 domain and HTTP wire types for
ReallyMe issuance infrastructure.

These Serde models implement specification-native OpenID4VCI HTTP JSON. They
are not cross-language SDK DTOs. SDK and RPC integrations use generated
messages from `reallyme-openid4vci-proto` and the bounded codec facade exposed by
`reallyme-openid4vci`.

Inbound JSON is size- and depth-bounded, rejects duplicate members, and applies
an explicit closed-object or specification-required extensible-object policy.
Credential and Notification Requests ignore unrecognized top-level parameters
as required by OpenID4VCI 1.0, while nested proof and encryption objects remain
closed. Errors use fixed typed reason codes and do not retain untrusted input.

Add the crate from crates.io with:

```sh
cargo add reallyme-openid4vci-types@0.1.1
```

Licensed under either the MIT License or the Apache License, Version 2.0.
