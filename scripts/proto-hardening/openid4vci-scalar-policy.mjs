// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const sensitive = (message, field, kind) => ({
  message,
  field,
  kind,
  sensitivity: "sensitive",
});

const publicScalar = (message, field, kind) => ({
  message,
  field,
  kind,
  sensitivity: "public",
});

// Closed-world classification for every bytes/string field in openid4vci.proto.
// Public is deliberately limited to stable protocol, format, and algorithm
// identifiers. URLs, deployment identifiers, claims metadata, public keys,
// and user-facing text are wiped because they remain useful correlators even
// when they are not cryptographic secrets.
export const OPENID4VCI_SCALAR_FIELD_CLASSIFICATIONS = Object.freeze([
  publicScalar("ProblemDetails", "type_uri", "string"),
  publicScalar("ProblemDetails", "title", "string"),
  sensitive("ProblemDetails", "instance", "string"),
  publicScalar("ProblemDetails", "error", "string"),
  sensitive("TxCode", "description", "string"),
  sensitive("AuthorizationCodeGrant", "issuer_state", "string"),
  sensitive("AuthorizationCodeGrant", "authorization_server", "string"),
  sensitive("PreAuthorizedCodeGrant", "pre_authorized_code", "string"),
  sensitive("PreAuthorizedCodeGrant", "authorization_server", "string"),
  sensitive("CredentialOffer", "credential_issuer", "string"),
  sensitive("CredentialOffer", "credential_configuration_ids", "string"),
  sensitive("CredentialOfferUri", "credential_offer_uri", "string"),
  publicScalar("CredentialSelector", "credential_configuration_id", "string"),
  sensitive("CredentialSelector", "credential_identifier", "string"),
  sensitive("Proofs", "jwt", "string"),
  sensitive("Proofs", "di_vp_json", "bytes"),
  sensitive("Proofs", "attestation", "string"),
  sensitive("CredentialResponseEncryption", "jwk_json", "bytes"),
  publicScalar("CredentialResponseEncryption", "enc", "string"),
  publicScalar("CredentialResponseEncryption", "zip", "string"),
  sensitive("CredentialEnvelope", "compact", "string"),
  sensitive("CredentialEnvelope", "json", "bytes"),
  sensitive("CredentialEnvelope", "binary", "bytes"),
  sensitive("ImmediateCredentialResponse", "notification_id", "string"),
  sensitive("DeferredCredentialResponse", "transaction_id", "string"),
  sensitive("DeferredCredentialRequest", "transaction_id", "string"),
  sensitive("NonceResponse", "c_nonce", "string"),
  sensitive("NotificationRequest", "notification_id", "string"),
  sensitive("NotificationRequest", "event_description", "string"),
  publicScalar("ProofTypeMetadata", "proof_signing_alg_values_supported", "string"),
  publicScalar("ProofTypeMetadataEntry", "proof_type", "string"),
  publicScalar("KeyAttestationsRequired", "key_storage", "string"),
  publicScalar("KeyAttestationsRequired", "user_authentication", "string"),
  publicScalar("CredentialSigningAlg", "named", "string"),
  publicScalar("CredentialConfiguration", "scope", "string"),
  publicScalar(
    "CredentialConfiguration",
    "cryptographic_binding_methods_supported",
    "string",
  ),
  sensitive("CredentialConfiguration", "claims_json", "bytes"),
  publicScalar("CredentialConfiguration", "vct", "string"),
  publicScalar("CredentialConfiguration", "doctype", "string"),
  sensitive("CredentialConfiguration", "credential_metadata_json", "bytes"),
  publicScalar(
    "CredentialRequestEncryptionMetadata",
    "alg_values_supported",
    "string",
  ),
  publicScalar(
    "CredentialRequestEncryptionMetadata",
    "enc_values_supported",
    "string",
  ),
  sensitive("CredentialRequestEncryptionMetadata", "jwks_json", "bytes"),
  publicScalar(
    "CredentialRequestEncryptionMetadata",
    "zip_values_supported",
    "string",
  ),
  publicScalar(
    "CredentialResponseEncryptionMetadata",
    "alg_values_supported",
    "string",
  ),
  publicScalar(
    "CredentialResponseEncryptionMetadata",
    "enc_values_supported",
    "string",
  ),
  publicScalar(
    "CredentialResponseEncryptionMetadata",
    "zip_values_supported",
    "string",
  ),
  sensitive(
    "CredentialConfigurationEntry",
    "credential_configuration_id",
    "string",
  ),
  sensitive("IssuerMetadata", "credential_issuer", "string"),
  sensitive("IssuerMetadata", "authorization_servers", "string"),
  sensitive("IssuerMetadata", "credential_endpoint", "string"),
  sensitive("IssuerMetadata", "nonce_endpoint", "string"),
  sensitive("IssuerMetadata", "deferred_credential_endpoint", "string"),
  sensitive("IssuerMetadata", "notification_endpoint", "string"),
]);
