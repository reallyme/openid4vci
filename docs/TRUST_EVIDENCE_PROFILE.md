# OpenID4VCI Trust Evidence Profile

This profile defines the fail-closed contract for key attestations, signed
Credential Issuer Metadata, and wallet-attestation evidence consumed by the
OpenID4VCI engine.

## Key Attestations

OpenID4VCI 1.0 Final Appendices D.1, F.1, F.3, and F.4 are implemented with
these invariants:

- the caller supplies trusted current time, maximum age, clock skew, and the
  algorithms permitted by the selected proof metadata and local policy;
- `iat` is mandatory, and `exp` is mandatory when key attestation is carried by
  a JWT proof; stale, future-issued, and expired values are distinct outcomes;
- public JWKs are bounded and validated according to RFC 7517 and RFC 7518;
  private/symmetric members, unsupported curves, invalid points, and duplicate
  key material are rejected before issuance;
- `key_storage`, `user_authentication`, `certification`, `status`, nonce,
  accepted algorithm, signer identity, and temporal claims remain in the
  verified receipt;
- the injected trust verifier returns purpose, policy version, immutable source
  snapshot, trust anchor, an explicit `evaluated_at`/`valid_until` interval,
  and status evidence evaluated within the current trusted clock-skew window;
  stale or future trust receipts are rejected with distinct typed outcomes; and
- direct attestation yields one credential-binding proof per verified key, and
  the resulting key count is checked against the advertised batch ceiling.

Unknown but bounded attack-potential-resistance identifiers remain typed as
unregistered values. They are therefore distinct from malformed input and can
be accepted or rejected explicitly by a policy revision.

Appendix D.2's `iso_18045_basic`, `iso_18045_enhanced-basic`,
`iso_18045_moderate`, and `iso_18045_high` values are all represented by
dedicated enum variants; only genuinely unknown bounded identifiers use the
unregistered variant.

JWT temporal processing follows RFC 7519 Sections 4.1.4 and 4.1.6. Algorithm
selection and explicit typing follow RFC 7515, RFC 7518, and RFC 8725 Sections
3.1 and 3.11. Unsupported critical JOSE extensions, including RFC 7797 unencoded
payloads, fail closed because they change signing-input semantics. RFC 8399 is not
applicable to these JWK/JWT decisions; it governs
internationalized X.509 name processing and belongs at the X.509 verifier
boundary.

## Signed Credential Issuer Metadata

The wallet accepts the `application/jwt` representation from OpenID4VCI 1.0
Final Sections 12.2.2 and 12.2.3 only through
`verify_signed_issuer_metadata`. The boundary requires the exact
`openidvci-issuer-metadata+jwt` type, a wallet-allowed asymmetric algorithm,
the mandatory `sub` and `iat` claims, optional `exp`, and exact simple-string
binding to both the retrieval Credential Issuer Identifier and the metadata's
`credential_issuer` value.

The trust adapter verifies the RFC 7515 signature and signer trust before the
payload becomes typed metadata. Its receipt records signer identity, optional
`iss` authorization, trust purpose, policy version, immutable source snapshot,
anchor, evaluation time, and validity limit. The validation context also names
the required signer-trust purpose: generic metadata-signer trust and EUDI WRPAC
trust are distinct enum values and cannot be substituted. A present `iss` that
is not explicitly bound by that receipt fails closed. This keeps generic
protocol claims in OpenID4VCI while permitting an EUDI adapter to supply and
require WRPAC-purpose evidence. Stale and future signer-trust receipts remain
distinct from an expired, stale, or future-issued metadata JWT.

## Typed Boundary Outcomes

Rust domain errors use non-payload enums. Cross-language, RPC, SDK, storage,
audit, telemetry, and conformance boundaries use the canonical
`reallyme.openid4vci.v1.OpenId4VciErrorReason` protobuf enum. Signature,
signer trust, status, time, algorithm policy, security-property policy,
attested-key, and invalid-provenance outcomes remain distinct internally;
HTTP OAuth responses intentionally project them to the coarse public errors
required by the protocol.

## Wallet Attestation Consumer Boundary

When wallet-attestation client authentication is enabled, the HTTP adapter
requires a `WalletAttestationEvidenceRecorder`. It records the exact
`VerifiedAttestationClientAuthentication` returned after SSI has verified PoP
with the key extracted from the same accepted attestation and consumed replay
state. The RFC 7638 client-instance key thumbprint and validated PoP claims are
not reconstructed from ambient request state.

Signer-provider trust, certificate/status provenance, and their rejected versus
indeterminate outcomes remain owned by the SSI verifier. Adding fields to the
SSI receipt does not require an OpenID4VCI flow fork because the recorder
receives that concrete receipt by reference.

## Conformance Evidence

`vectors/openid4vci-trust-evidence.json` fixes the validation clock and policy
for portable key-attestation and signed-metadata cases. Unit and integration
coverage additionally exercises malformed and oversized input, duplicate
members and keys, invalid public keys, time boundaries, algorithm policy,
security-property policy, trust/status outcomes, optional issuer binding,
per-key issuance, and the post-verification batch ceiling.
