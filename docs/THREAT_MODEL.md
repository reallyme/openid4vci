# OpenID4VCI Protocol Threat Model

This document describes the protocol-level threats to OpenID4VCI credential
issuance as implemented by this workspace, and the mitigations enforced in code.
It complements [`SECURITY.md`](SECURITY.md) (vulnerability disclosure) and
the executable protocol and conformance tests in this repository.

## Assets and trust boundaries

- **Credentials** and their signing keys (issuer-held).
- **Access tokens** authorizing issuance, and their sender-constraint keys.
- **Wallet key material** proven through key proofs and key attestations.
- **Server-issued challenges**: `c_nonce`, DPoP nonce, attestation challenge.

The transport-agnostic core (`crates/types`, `crates/issuer`,
`crates/wallet`, `crates/attestation`, `reallyme-openid-oauth`) makes protocol
decisions over already-parsed inputs. The supported HTTP adapter composes those
dependencies and enforces transport authorization before invoking issuer logic.
HTTP, storage, signing, encryption, and trust resolution adapters must uphold
the boundary contracts below. Everything an attacker can reach is untrusted
until validated.

## Threats and mitigations

### Replay

- **Captured Credential Request replay.** Each key proof carries a server-issued
  `c_nonce`. The Nonce Endpoint returns a versioned expiry and random identifier
  authenticated with HMAC, without allocating server-side issuance state. The
  Credential Endpoint authenticates the nonce and records the identifier in a
  bounded replay set, partitioned by the validated access-token grant, only
  after successful validation. One token can exhaust only its own partition;
  a replayed request fails because the nonce is already consumed, while forged
  and expired values fail before they can occupy replay capacity.
- **DPoP / attestation PoP replay.** DPoP and wallet-attestation PoP proofs bind
  a unique `jti` and an `iat`; the `check_replay` hook is mandatory (no default
  implementation) and always invoked, so an adapter cannot silently skip it.
- **`iat` freshness.** DPoP / PoP acceptance windows are computed per request
  from a wall-clock `Clock`, not frozen at process start, bounding how long any
  intercepted proof can be replayed.
- **PAR request-URI replay.** A preliminary Authorization Endpoint visit leaves
  an accepted RFC 9126 `request_uri` reusable until the authentication action
  completes, as required by the FAPI profile. The composed issuer adapter then
  consumes it atomically before any fallible callback or code-generation work.
  Concurrent completion, reuse after completion, and reuse after user rejection
  therefore produce only a callback-bound `invalid_request_uri` error and cannot
  mint another authorization code.

### Token theft and sender-constraint bypass

- **Stolen access token used with an attacker key.** Protected resources require
  an injected access-token validator. DPoP proofs are bound to the token through
  `ath` and to its confirmed `cnf.jkt` through an RFC 7638 JWK thumbprint
  comparison. A missing confirmation thumbprint fails closed when DPoP is
  enabled.
- **Algorithm confusion / symmetric-key forgery.** DPoP and attestation PoP
  headers are restricted to an asymmetric-algorithm allowlist; `none`, symmetric
  `alg` values, and symmetric (`oct` / private) JWK material are rejected before
  any injected verifier runs.
- **Header smuggling.** Exactly one of each security header (`DPoP`,
  `OAuth-Client-Attestation`, `-PoP`) is accepted; duplicates fail closed.
- **Bearer-value memory retention.** The example issuer indexes authorization
  codes, access tokens, and refresh tokens by SHA-256 digest; raw bearer values
  are not retained as hash-map keys after response construction.

### Metadata and target spoofing

- **Issuer identifier spoofing.** Credential Issuer Identifiers and offer issuers
  are validated as HTTPS URLs with no query or fragment (§12.2.1); AS metadata
  enforces `issuer` equality (RFC 8414).
- **DPoP `htu` target spoofing.** The `htu` comparison target is always derived
  from the trusted, configured issuer identifier and the request path; a client-
  or proxy-supplied scheme/authority in an absolute-form request line is ignored.
- **Authorization callback injection.** An injected Authorization Server error
  is always returned directly. Redirects occur only through an explicit
  `AuthorizationResponse` produced after the Authorization Server has validated
  the registered callback; the HTTP adapter never promotes a request parameter
  into an error redirect destination.
- **Credential-offer issuer mix-up.** Public wallet token and credential
  builders require a `ValidatedIssuance` bound to trusted issuer metadata and
  one allow-listed authorization server. Offer-initiated interactions also bind
  one selected grant and restrict configuration-ID requests to the offer;
  wallet-initiated interactions derive that restriction from validated issuer
  metadata. Pre-authorized codes cannot be serialized before offer binding.
- **Content-type smuggling.** Credential, deferred, OAuth, and holder-harness
  inputs recognize one exact, case-insensitive media type with optional
  parameters. Duplicate or substring-only `Content-Type` values fail closed.

### Credential substitution and confidentiality

- **Response-encryption key substitution.** A Credential Request that asks for
  response encryption MUST itself arrive encrypted (§8.2); a plaintext request
  carrying `credential_response_encryption` is rejected, preventing a middlebox
  from swapping the wallet's encryption key. Encrypted request bodies are
  decrypted through an injected `CredentialRequestDecryptor`.
- **Proof-key confusion.** Key proofs must be typed `openid4vci-proof+jwt`,
  carry a required `iat`, and bind the key through exactly one JOSE header
  mechanism (`jwk`, or `kid`/`x5c` via an injected resolver); the draft-era
  payload `cnf.jwk` binding is not accepted. The JWS `alg` must match the bound
  key (no HS-with-public-key path). Private and symmetric JWK members are
  rejected before their values are materialized.
- **Attested-key claim injection.** Attested JWKs are reduced to the verified
  public-key members before entering credential `cnf.jwk`; unknown extensions
  are not propagated as trusted claims. Ed25519 attested keys are decompressed
  and weak/small-order points are rejected even when the attestation signature
  itself was valid.
- **Insufficient assurance.** High-assurance profiles (HAIP) require a verified,
  key-scoped attestation; issuance fails closed when the policy requires one and
  the verified proof set does not include it. Wallet attestation authenticates a
  wallet client and never substitutes for evidence bound to a specific key.

### Denial of service

- **Oversized inputs.** JSON bodies, compact proof JWTs, attestation JWTs, and
  encrypted response bodies are length-bounded with named limits before base64
  decode or serde parsing.
- **Proof fan-out.** The Credential Request `proofs` array is bounded by the
  advertised `batch_credential_issuance.batch_size` (default one) before any
  signature verification, so a request cannot force unbounded verification work.
- **Credential authorization substitution.** The protected Credential Endpoint
  authorizes the canonical selector through the required access-token validator
  before proof verification or issuance. The resulting typed authorization
  context carries an opaque subject/grant handle and the approved credential
  configuration into both immediate and deferred issuer providers. The
  validator distinguishes an unknown selector from a known selector outside the token grant, preserving the
  protocol's `unknown_credential_*` errors without weakening the RFC 6750
  `insufficient_scope` denial.
- **Deferred and notification substitution.** The access-token validator binds
  deferred transaction and notification identifiers to the requester. A
  deferred poll supplies fresh response-encryption parameters independently of
  the initial Credential Request, as required by OpenID4VCI 1.0 §9.1. The
  resulting credential response is encrypted to that freshly validated key;
  transport confidentiality remains the responsibility of the required HTTPS
  channel.
- **Destructive invalid encryption input.** The selected encryption backend
  validates the complete JWK, curve, coordinates, content algorithm, and
  compression parameters before a proof nonce is consumed, issuance runs, or
  a single-use deferred transaction is resolved.
- **Abandoned deferred transactions.** The in-memory reference store requires
  an explicit future expiry, prunes expired records before enforcing capacity,
  and applies the same clock during atomic take. Production stores must retain
  those expiry and single-use semantics durably.
- **Attested-key fan-out.** Key attestations bound the number of attested keys
  and require each entry to be a JWK object.

### Wallet-attestation and wallet privacy

- **PoP audience binding.** Wallet-attestation PoP `aud` must equal the
  Authorization Server issuer identifier, preventing cross-issuer replay of a PoP.
- **Holder secret handling.** Pre-authorized codes and transaction codes are held
  in zeroizing buffers, are never derived into loggable `Debug`/`Clone` forms, and
  reach plaintext only at the deliberate wire-serialization boundary.

## Residual risks and assumptions

- Concrete DPoP signature verification, wallet/key attestation trust-chain
  verification, `kid`/`x5c` resolution, and JWE encryption/decryption are
  injected adapters; their correctness is assumed and must be covered by the
  adapter's own tests and cross-lane vectors.
- Single-use stores, replay stores, and deferred/notification stores must be
  backed by durable, replica-shared storage in production; the in-memory
  implementations are single-process only.
- TLS termination remains deployment-owned. Access-token validation, exact
  credential-selector authorization, deferred/notification ownership, and
  `cnf.jkt` extraction are mandatory injected resource-server boundaries.
- The example issuer enables TLS only when a complete, valid certificate/key
  pair is configured. A partial, empty, or non-Unicode TLS configuration is a
  startup error rather than a plaintext fallback, and the configured transport
  must match the issuer identifier's scheme.
