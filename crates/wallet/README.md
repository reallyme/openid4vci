# reallyme-openid4vci-wallet

Wallet-side protocol support for OpenID for Verifiable Credential Issuance
1.0.

The crate provides validated builders and state transitions for Credential
Offers, authorization and token requests, proof-bearing Credential Requests,
signed issuer metadata, and encrypted Credential Responses. Network transport,
secure key storage, user consent, and durable wallet storage are supplied by the
integrating application.

## Security boundary

- Untrusted JSON and metadata are validated before becoming domain types.
- Referenced offers are revalidated after retrieval.
- Token and credential builders require a `ValidatedIssuance` bound to issuer
  metadata and an allow-listed authorization server. Offer-initiated flows also
  bind the selected grant and offered configurations; wallet-initiated flows
  bind configurations directly from validated issuer metadata.
- Key-proof signing requires a signer-reported RFC 7638 thumbprint that matches
  the public JWK embedded in the proof.
- Proof and response-encryption inputs are bounded and typed.
- Plaintext serialization is unavailable when issuer metadata requires request
  encryption or the Wallet requests an encrypted response.
- A plaintext response is rejected after response encryption was requested.
- Pre-authorized codes, authorization codes, and transaction codes use
  secret-bearing owners with redacted debug output and best-effort zeroization.

Add the crate from crates.io with:

```sh
cargo add reallyme-openid4vci-wallet@0.1.0
```

Licensed under either the MIT License or the Apache License, Version 2.0.
