# OpenID4VCI Issuer

`openid4vci-issuer` is the transport-independent issuer endpoint engine for the
ReallyMe OpenID4VCI implementation. Storage, signing, trust, and transport are
provided through explicit application-owned boundaries.

The crate is protocol infrastructure rather than a deployable authorization or
credential-issuer service.

See the [ReallyMe OpenID4VCI repository](https://github.com/reallyme/openid4vci)
for architecture, security, and conformance documentation.

## `reallyme_zk_v1` credential responses

`CommonRootIssuedCredential::issue_from_authorized_claims` computes the
approved common-root transcript through `reallyme-zk-api`, signs that exact
root through `reallyme-credential`, and prepares the response without replacing
signed fields. SHA-256 and Poseidon2 commitments use the matching ZK API
transcript and are selected by the signed SSI commitment metadata. The issuer
supplies canonical claims from its own issuance decision, the wallet request's
`CommonRootIssuanceRequestBinding`, a verified holder key, and
`IssuanceStatusEvidence`. The request binding carries the lineage-tag
commitment, wallet-opening commitment, and opaque lineage leaf that must later
match the OpenID4VCI request byte-for-byte. The status context supplies the
signed list, independently trusted signature verifier, current time, and
freshness policy. The constructor authenticates the list before invoking the
credential signer.

For an SSI credential that the application has already issued,
`CommonRootIssuedCredential::from_authorized_common_root_issuance`
accepts its proof binding and the same authoritative claims. The application
also supplies the independently trusted issuer public key, verified holder key,
and status context. The constructor checks the issuer and list signatures,
claim root, holder binding, and status pointer before packaging the response.

`CommonRootCredentialEncoder` emits one OpenID4VCI credential string:
unpadded base64url of the generated Buffa `ReallyMeZkV1Credential` message.
That message carries the embedded SSI protobufs, public proof binding, holder
key, wallet request commitments, opaque lineage leaf, and wire version.
Encoders and receivers bound message size and depth and reject unknown fields
or versions.

For `reallyme_zk_v1`, the credential request also carries a compact Buffa
`ReallyMeZkV1IssuanceRequest`. The encoder treats that request as a wallet
reconciliation guard: it must be canonical, it must identify the same claims
root and holder key as the issuer-prepared payload, and its lineage/opening
commitment and opaque-lineage-leaf fields must exactly match the fields bound
into the issuer-prepared payload. It does not make wallet-supplied claim roots
authoritative; issuer
applications must derive the approved claim names and raw claim bytes from
their own issuance decision before calling the authorized constructor.

`PassThroughCredentialEncoder` rejects `ReallyMeZkV1`. This format must route
through `CommonRootCredentialEncoder` so the generated Buffa payload,
holder key, signed root binding, status evidence, and wallet issuance intent are
validated before transport.

The issuer application signs the SSI envelope, claim-root and holder-key
bindings, and current status list. The receiving wallet independently checks
issuer trust, signatures, holder binding, validity, and status before accepting
the credential.
