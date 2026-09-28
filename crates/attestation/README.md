# OpenID4VCI Attestation

`openid4vci-attestation` provides the typed wallet-attestation and key-attestation
models used by the ReallyMe OpenID4VCI issuer and protocol facade.

The crate validates attested public keys and security properties while leaving
trust-anchor selection and external evidence acquisition to the integrating
application.

See the [ReallyMe OpenID4VCI repository](https://github.com/reallyme/openid4vci)
for architecture, security, and conformance documentation.
