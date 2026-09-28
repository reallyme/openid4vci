#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync, readdirSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const failures = [];

const sensitiveOwners = new Map([
  [
    "crates/attestation/src/model.rs",
    [
      "CertificationReference",
      "KeyAttestationStatusReference",
      "KeyAttestationTrustEvidence",
      "VerifiedBindingKey",
    ],
  ],
  [
    "crates/attestation/src/verify_key_attestation.rs",
    [
      "KeyAttestationValidationContext",
      "ParsedKeyAttestation",
      "VerifiedKeyAttestation",
    ],
  ],
  [
    "crates/http/src/serve_oauth.rs",
    [
      "AuthorizationResponse",
      "OAuthParameters",
      "OAuthRequestHeaders",
      "PushedAuthorizationResponse",
      "TokenResponse",
    ],
  ],
  [
    "crates/issuer/src/proof/process.rs",
    ["UnverifiedProofClaims"],
  ],
  [
    "crates/issuer/src/proof/verify.rs",
    ["VerifiedProof", "VerifiedProofSet"],
  ],
  ["crates/issuer/src/encode.rs", ["IssuedCredential"]],
  ["crates/issuer/src/encrypt.rs", ["CredentialRequestJson", "EncryptedCredentialResponse"]],
  ["crates/issuer/src/store.rs", ["DeferredIssuance"]],
  [
    "crates/wallet/src/metadata.rs",
    [
      "ParsedSignedIssuerMetadata",
      "SignedIssuerMetadataJwt",
      "SignedIssuerMetadataValidationContext",
      "SignedMetadataTrustEvidence",
    ],
  ],
  ["crates/wallet/src/request.rs", ["WalletCredentialRequest"]],
  ["crates/types/src/credential_error.rs", ["CredentialErrorResponse"]],
  ["crates/types/src/nonce.rs", ["NonceResponse"]],
  ["crates/types/src/notification.rs", ["NotificationRequest"]],
  [
    "crates/types/src/offer.rs",
    ["AuthorizationCodeGrant", "CredentialOffer", "PreAuthorizedCodeGrant", "TxCode"],
  ],
  [
    "crates/types/src/request.rs",
    ["CredentialRequest", "CredentialResponseEncryption", "CredentialSelector", "Proofs"],
  ],
  [
    "crates/types/src/response.rs",
    ["CredentialEnvelope", "CredentialResponse", "DeferredCredentialRequest"],
  ],
]);

const redactedOwners = new Map([
  ["crates/issuer/src/encode.rs", ["IssuedCredential"]],
  ["crates/issuer/src/encrypt.rs", ["EncryptedCredentialResponse"]],
  ["crates/types/src/offer.rs", ["ParsedCredentialOffer"]],
  [
    "crates/types/src/request.rs",
    ["CredentialRequest", "CredentialResponseEncryption", "CredentialSelector", "Proofs"],
  ],
  ["crates/wallet/src/request.rs", ["WalletCredentialRequest"]],
]);

const closedJsonOwners = new Map([
  [
    "crates/types/src/credential_error.rs",
    [
      "CredentialErrorResponse",
      "DeferredCredentialErrorResponse",
      "NotificationErrorResponse",
    ],
  ],
  ["crates/types/src/nonce.rs", ["NonceRequest", "NonceResponse"]],
  [
    "crates/types/src/offer.rs",
    [
      "AuthorizationCodeGrant",
      "PreAuthorizedCodeGrant",
      "TxCode",
    ],
  ],
  [
    "crates/types/src/request.rs",
    ["CredentialResponseEncryption", "Proofs"],
  ],
]);

const extensibleJsonOwners = new Map([
  ["crates/types/src/notification.rs", ["NotificationRequest"]],
  ["crates/types/src/offer.rs", ["CredentialOffer", "CredentialOfferGrant"]],
  ["crates/types/src/request.rs", ["CredentialRequest"]],
  [
    "crates/types/src/response.rs",
    ["CredentialEnvelope", "CredentialResponse", "DeferredCredentialRequest"],
  ],
]);

const reviewedCalls = new Map([
  ["crates/attestation/src/validate_key_attestation_claims.rs", ["from_value"]],
  [
    "crates/attestation/src/verify_key_attestation.rs",
    ["from_str", "from_str", "from_str"],
  ],
  [
    "crates/http/src/axum_holder_harness.rs",
    ["from_str", "from_str"],
  ],
  ["crates/http/src/respond_holder_harness.rs", ["to_vec"]],
  ["crates/http/src/serve_oauth.rs", ["to_string"]],
  ["crates/http/src/validate_http_security.rs", ["to_value"]],
  ["crates/issuer/src/encrypt_jwe.rs", ["to_vec"]],
  ["crates/issuer/src/encrypt_jwe/compressed_response.rs", ["to_vec"]],
  [
    "crates/issuer/src/jose.rs",
    ["from_value", "from_value", "to_value"],
  ],
  ["crates/issuer/src/proof/process.rs", ["from_str"]],
  ["crates/proto-codec/src/decode.rs", ["from_str"]],
  ["crates/proto-codec/src/encode.rs", ["to_writer"]],
  ["crates/proto-codec/src/json.rs", ["to_vec"]],
  ["crates/types/src/validation.rs", ["from_str", "to_string"]],
  ["crates/wallet/src/metadata/verify.rs", ["from_str", "from_str", "from_str"]],
]);

const collectRustFiles = (directory) => {
  const files = [];
  for (const entry of readdirSync(resolve(root, directory))) {
    const relative = `${directory}/${entry}`;
    const metadata = statSync(resolve(root, relative));
    if (metadata.isDirectory()) {
      if (!["examples", "generated", "tests"].includes(entry)) {
        files.push(...collectRustFiles(relative));
      }
    } else if (entry.endsWith(".rs")) {
      files.push(relative);
    }
  }
  return files;
};

const directCalls = (path) => {
  let source = readFileSync(resolve(root, path), "utf8");
  const testModule = source.indexOf("\n#[cfg(test)]\nmod tests");
  if (testModule >= 0) {
    source = source.slice(0, testModule);
  }
  return [...source.matchAll(/serde_json::(from_[a-z_]+|to_[a-z_]+)/g)]
    .map((match) => match[1])
    .sort();
};

const observedPaths = new Set();
for (const path of collectRustFiles("crates")) {
  const calls = directCalls(path);
  if (calls.length === 0) {
    continue;
  }
  observedPaths.add(path);
  const reviewed = reviewedCalls.get(path);
  if (reviewed === undefined) {
    failures.push(`${path}: unreviewed direct serde_json boundary (${calls.join(", ")})`);
    continue;
  }
  const expected = [...reviewed].sort();
  if (JSON.stringify(calls) !== JSON.stringify(expected)) {
    failures.push(
      `${path}: direct serde_json calls changed; expected ${expected.join(", ")}, observed ${calls.join(", ")}`,
    );
  }
}

for (const path of reviewedCalls.keys()) {
  if (!observedPaths.has(path)) {
    failures.push(`${path}: reviewed serde_json boundary disappeared; update the inventory`);
  }
}

for (const [path, owners] of sensitiveOwners) {
  const source = readFileSync(resolve(root, path), "utf8");
  for (const owner of owners) {
    const rawDebug = new RegExp(
      `#\\[derive\\([^\\]]*\\bDebug\\b[^\\]]*\\)\\]\\s*(?:pub\\s+)?(?:struct|enum)\\s+${owner}\\b`,
      "s",
    );
    if (rawDebug.test(source)) {
      failures.push(`${path}: sensitive owner ${owner} derives raw Debug`);
    }
    const explicitDrop = source.includes(`impl Drop for ${owner}`);
    const zeroizeOnDrop = new RegExp(
      `#\\[derive\\([^\\]]*\\bZeroizeOnDrop\\b[^\\]]*\\)\\]\\s*(?:pub\\s+)?(?:struct|enum)\\s+${owner}\\b`,
      "s",
    ).test(source);
    const zeroizingStorage = new RegExp(
      `(?:struct|enum)\\s+${owner}\\b[^}]*Zeroizing\\s*<`,
      "s",
    ).test(source);
    // These wrappers contain only owners whose own Drop implementations clear
    // the sensitive storage. Recording the transitive policy explicitly keeps
    // this check accurate without adding redundant Drop implementations that
    // would prevent safe field moves.
    const transitivelyOwned = [
      "CredentialEnvelope",
      "DeferredIssuance",
      "VerifiedProofSet",
    ].includes(owner);
    if (!explicitDrop && !zeroizeOnDrop && !zeroizingStorage && !transitivelyOwned) {
      failures.push(`${path}: sensitive owner ${owner} has no drop-time zeroization policy`);
    }
  }
}

for (const [path, owners] of extensibleJsonOwners) {
  const source = readFileSync(resolve(root, path), "utf8");
  for (const owner of owners) {
    const closedModel = new RegExp(
      `#\\[serde\\(deny_unknown_fields\\)\\]\\s*pub struct ${owner}\\b`,
      "s",
    );
    if (closedModel.test(source) || !source.includes("EXTENSIBLE_DOCUMENT_JSON")) {
      failures.push(`${path}: extensible JSON owner ${owner} does not use the extensible policy`);
    }
  }
}

for (const [path, owners] of redactedOwners) {
  const source = readFileSync(resolve(root, path), "utf8");
  for (const owner of owners) {
    if (!source.includes(`impl Debug for ${owner}`)) {
      failures.push(`${path}: sensitive owner ${owner} has no redacted Debug policy`);
    }
  }
}

for (const [path, owners] of closedJsonOwners) {
  const source = readFileSync(resolve(root, path), "utf8");
  for (const owner of owners) {
    const closedModel = new RegExp(
      `#\\[serde\\(deny_unknown_fields\\)\\]\\s*pub struct ${owner}\\b`,
      "s",
    );
    if (!closedModel.test(source)) {
      failures.push(`${path}: closed JSON owner ${owner} does not deny unknown fields`);
    }
  }
}

const domainJsonPolicy = readFileSync(
  resolve(root, "crates/types/src/validation.rs"),
  "utf8",
);
for (const requiredPolicy of [
  "MAX_JSON_BYTES: usize = 65_536",
  "MAX_JSON_OUTPUT_BYTES: usize = 262_144",
  "MAX_JSON_NESTING_DEPTH: usize = 128",
  "REJECT_DUPLICATE_JSON_MEMBERS: bool = true",
  "CLOSED_OPERATION_JSON",
  "EXTENSIBLE_DOCUMENT_JSON",
  "malformed_reason: Reason::InvalidJson",
  "oversized_reason: Reason::PayloadTooLarge",
]) {
  if (!domainJsonPolicy.includes(requiredPolicy)) {
    failures.push(`crates/types/src/validation.rs: missing policy ${requiredPolicy}`);
  }
}

const metadataSource = [
  "crates/types/src/metadata/describe.rs",
  "crates/types/src/metadata/validate.rs",
]
  .map((path) => readFileSync(resolve(root, path), "utf8"))
  .join("\n");
if (
  !metadataSource.includes("parse_json_rejecting_top_level_members(") ||
  !metadataSource.includes("EXTENSIBLE_DOCUMENT_JSON") ||
  !metadataSource.includes('FORBIDDEN_METADATA_MEMBERS: [&str; 1] = ["batch_credential_endpoint"]')
) {
  failures.push("crates/types/src/metadata: metadata parser is not explicitly extensible");
}

const responseSource = readFileSync(resolve(root, "crates/types/src/response.rs"), "utf8");
if (
  !responseSource.includes("..EXTENSIBLE_DOCUMENT_JSON") ||
  !responseSource.includes("fn parse_credential_response_object(") ||
  !responseSource.includes("zeroize_json_strings(&mut value);")
) {
  failures.push("crates/types/src/response.rs: missing extensible response parsing policy");
}

const axumIssuerSource = [
  "crates/http/src/axum_issuer/handle.rs",
  "crates/http/src/axum_issuer/respond.rs",
]
  .map((path) => readFileSync(resolve(root, path), "utf8"))
  .join("\n");
for (const requiredBodyPolicy of [
  "Result<Zeroizing<Vec<u8>>, ProblemDetails>",
  "Result<Zeroizing<String>, ProblemDetails>",
  ".try_into_mut()",
  "mutable.as_mut().zeroize()",
  "invalid_bytes.zeroize()",
]) {
  if (!axumIssuerSource.includes(requiredBodyPolicy)) {
    failures.push(
      `crates/http/src/axum_issuer: missing request-body ownership policy ${requiredBodyPolicy}`,
    );
  }
}

if (failures.length !== 0) {
  console.error("JSON boundary checks failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(`JSON boundary checks passed for ${reviewedCalls.size} reviewed source files`);
