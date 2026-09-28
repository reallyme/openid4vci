#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const failures = [];

const read = (path) => readFileSync(resolve(root, path), "utf8");

const requireText = (path, needle) => {
  if (!read(path).includes(needle)) {
    failures.push(`${path}: missing required marker ${JSON.stringify(needle)}`);
  }
};

const rejectText = (path, needle) => {
  if (read(path).includes(needle)) {
    failures.push(`${path}: contains forbidden boundary text ${JSON.stringify(needle)}`);
  }
};

const extractProtoBlock = (path, declarationKind, name) => {
  const source = read(path);
  const marker = `${declarationKind} ${name}`;
  const declarationIndex = source.indexOf(marker);
  if (declarationIndex === -1) {
    failures.push(`${path}: missing ${marker}`);
    return undefined;
  }

  const openingBrace = source.indexOf("{", declarationIndex + marker.length);
  if (openingBrace === -1) {
    failures.push(`${path}: ${marker} has no opening brace`);
    return undefined;
  }

  let depth = 1;
  for (let index = openingBrace + 1; index < source.length; index += 1) {
    if (source[index] === "{") {
      depth += 1;
    } else if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) {
        return source.slice(openingBrace + 1, index);
      }
    }
  }

  failures.push(`${path}: ${marker} has no closing brace`);
  return undefined;
};

const requireSequentialWireNumbers = (
  path,
  declarationKind,
  name,
  firstNumber,
) => {
  const block = extractProtoBlock(path, declarationKind, name);
  if (block === undefined) {
    return;
  }

  const assignmentPattern =
    declarationKind === "enum"
      ? /^\s*[A-Z][A-Z0-9_]*\s*=\s*(\d+)\s*;/gmu
      : /^\s*(?:repeated\s+)?[A-Za-z][A-Za-z0-9_.]*\s+[a-z][a-z0-9_]*\s*=\s*(\d+)(?:\s*\[[^\]]+\])?\s*;/gmu;
  const numbers = [...block.matchAll(assignmentPattern)].map((match) =>
    Number.parseInt(match[1], 10),
  );
  for (const [offset, actual] of numbers.entries()) {
    const expected = firstNumber + offset;
    if (actual !== expected) {
      failures.push(
        `${path}: ${declarationKind} ${name} wire number ${actual} is out of sequence; expected ${expected}`,
      );
    }
  }
};

const collectRustFiles = (directory) => {
  const files = [];
  for (const entry of readdirSync(resolve(root, directory))) {
    const relative = `${directory}/${entry}`;
    const metadata = statSync(resolve(root, relative));
    if (metadata.isDirectory()) {
      files.push(...collectRustFiles(relative));
    } else if (entry.endsWith(".rs")) {
      files.push(relative);
    }
  }
  return files;
};

const messageSchema =
  "crates/proto/proto/reallyme/openid4vci/v1/openid4vci.proto";
const serviceSchema =
  "crates/proto/proto/reallyme/openid4vci/v1/openid4vci_service.proto";

rejectText("Cargo.toml", "connectrpc");
rejectText("crates/proto/Cargo.toml", "connectrpc");
requireText("Cargo.toml", '"crates/proto-codec"');
requireText("crates/proto-codec/Cargo.toml", 'name = "openid4vci-proto-codec"');
requireText("crates/proto-codec/Cargo.toml", "publish = true");
requireText("crates/types/Cargo.toml", 'name = "reallyme-openid4vci-types"');
requireText("crates/types/Cargo.toml", "publish = true");
requireText("crates/proto/Cargo.toml", 'name = "reallyme-openid4vci-proto"');
requireText("crates/proto/Cargo.toml", "publish = true");
requireText(
  ".github/workflows/crates-package-preflight.yml",
  "node scripts/publish-crates-in-order.mjs inspect",
);
requireText("scripts/publish-crates-in-order.mjs", '"--locked"');
requireText(
  "scripts/publish-crates-in-order.mjs",
  '"reallyme-openid4vci-proto"',
);
requireText(
  "scripts/publish-crates-in-order.mjs",
  '"reallyme-openid4vci-types"',
);
rejectText("buf.gen.yaml", "protoc-gen-connect");
rejectText("buf.gen.yaml", "bufbuild/es");
requireText(
  "scripts/harden-generated-openid4vci-proto.mjs",
  'from "./proto-hardening/core.mjs"',
);
requireText(
  "scripts/harden-generated-openid4vci-proto.mjs",
  "OPENID4VCI_SCALAR_FIELD_CLASSIFICATIONS",
);
requireText(
  "scripts/proto-hardening/core.mjs",
  "export function hardenGeneratedProto",
);
requireText("scripts/proto-hardening/core.mjs", "parseProtoContracts");
rejectText(messageSchema, "service OpenId4VciIssuerService");
requireText(serviceSchema, 'import "reallyme/openid4vci/v1/openid4vci.proto";');
requireText(serviceSchema, "service OpenId4VciIssuerService");
requireText(messageSchema, "rejects duplicate object keys");
requireText(messageSchema, "262144 bytes per value");
requireText(messageSchema, "nesting deeper than 64 containers");
requireText(messageSchema, "message ProblemDetails");
requireText(messageSchema, "message OpenId4VciOperationRequest");
requireText(messageSchema, "message OpenId4VciOperationResult");
requireText(messageSchema, "message OpenId4VciOperationResponse");
rejectText(messageSchema, "CodecProtoResultEnvelope");
rejectText("crates/proto-codec/src/operation.rs", "process_proto(");

const schemaSource = read(messageSchema);
for (const match of schemaSource.matchAll(/^enum\s+([A-Za-z][A-Za-z0-9_]*)\s*\{/gmu)) {
  requireSequentialWireNumbers(messageSchema, "enum", match[1], 0);
}
for (const match of schemaSource.matchAll(/^message\s+([A-Za-z][A-Za-z0-9_]*)\s*\{/gmu)) {
  requireSequentialWireNumbers(messageSchema, "message", match[1], 1);
}

if (existsSync(resolve(root, "crates/proto/src/generated/connect"))) {
  failures.push("message-only proto crate contains generated Connect Rust");
}
if (existsSync(resolve(root, "protos/reallyme/openid4vci/v1/openid4vci.proto"))) {
  failures.push("legacy top-level OpenID4VCI schema must not return");
}
for (const platformPath of [
  "crates/ffi",
  "crates/jni",
  "crates/wasm",
  "packages/android",
  "packages/kotlin",
  "packages/kotlin-android",
  "packages/swift",
  "packages/ts",
  "packages/typescript",
  "packages/wasm",
]) {
  if (existsSync(resolve(root, platformPath))) {
    failures.push(
      `${platformPath}: platform bindings and packaging must remain owned by reallyme/identity`,
    );
  }
}
for (const platformWorkflow of [
  ".github/workflows/android-package-preflight.yml",
  ".github/workflows/jvm-package-preflight.yml",
  ".github/workflows/npm-package-preflight.yml",
  ".github/workflows/swift-package-preflight.yml",
  ".github/workflows/xcframework-package-preflight.yml",
]) {
  if (existsSync(resolve(root, platformWorkflow))) {
    failures.push(
      `${platformWorkflow}: platform package workflows must remain owned by reallyme/identity`,
    );
  }
}

for (const dependency of [
  "openid4vci-attestation",
  "reallyme-openid4vci-wallet",
  "openid4vci-issuer",
  "openid4vci-profiles",
  "openid4vci-types",
  "reallyme-ssi-proto",
]) {
  rejectText("crates/proto/Cargo.toml", dependency);
}
for (const moduleName of [
  "convert",
  "decode",
  "encode",
  "error",
  "limits",
  "map_error_reason",
]) {
  rejectText("crates/proto/src/lib.rs", `mod ${moduleName}`);
}

for (const domainManifest of [
  "crates/attestation/Cargo.toml",
  "crates/wallet/Cargo.toml",
  "crates/issuer/Cargo.toml",
  "crates/profiles/Cargo.toml",
  "crates/types/Cargo.toml",
]) {
  rejectText(domainManifest, "openid4vci-proto");
  rejectText(domainManifest, "openid4vci-proto-codec");
  rejectText(domainManifest, "openid4vci-http");
  rejectText(domainManifest, "axum");
}
rejectText("crates/proto-codec/Cargo.toml", "openid4vci-http");
rejectText("crates/proto-codec/Cargo.toml", "axum");
requireText("crates/http/Cargo.toml", 'name = "openid4vci-http"');
requireText("crates/http/Cargo.toml", "publish = true");
requireText("crates/http/Cargo.toml", "openid4vci-proto-codec");
rejectText("crates/http/Cargo.toml", "openid4vci-runtime");
rejectText("crates/openid4vci/Cargo.toml", "openid4vci-runtime");
rejectText("crates/openid4vci/src/lib.rs", "openid4vci_runtime");
rejectText("crates/http/src/lib.rs", "mod issuer_service");

requireText(
  "crates/proto-codec/src/decode.rs",
  ".with_recursion_limit(OPENID4VCI_PROTO_RECURSION_LIMIT)",
);
requireText(
  "crates/proto-codec/src/decode.rs",
  "remaining_depth: OPENID4VCI_PROTO_JSON_RECURSION_LIMIT",
);
requireText(
  "crates/proto-codec/src/decode.rs",
  "ProtoJsonStructureError::DuplicateMember",
);
requireText(
  "crates/proto-codec/src/json.rs",
  "JsonPolicyViolation::DuplicateKey",
);
requireText(
  "crates/proto-codec/src/convert/convert_values.rs",
  "pub fn problem_details_from_proto",
);
requireText(
  "crates/proto-codec/tests/protojson_fixture_tests.rs",
  "fn problem_details_fixture_has_binary_json_and_domain_parity",
);

const protoJsonFixtures = [
  "credential-offer.json",
  "issuer-metadata.json",
  "credential-request.json",
  "credential-response.json",
  "deferred-credential-request.json",
  "notification-request.json",
  "problem-details.json",
];
for (const fixture of protoJsonFixtures) {
  const path = `crates/proto/tests/fixtures/protojson/${fixture}`;
  if (!existsSync(resolve(root, path))) {
    failures.push(`${path}: missing golden ProtoJSON fixture`);
  }
}
for (const fixture of [
  "credential-offer.pb.hex",
  "issuer-metadata.pb.hex",
  "credential-request.pb.hex",
  "credential-response.pb.hex",
  "deferred-credential-request.pb.hex",
  "notification-request.pb.hex",
  "problem-details.pb.hex",
]) {
  const path = `crates/proto/tests/fixtures/protobuf/${fixture}`;
  if (!existsSync(resolve(root, path))) {
    failures.push(`${path}: missing exact protobuf wire fixture`);
  }
}
requireText(
  "crates/proto/tests/fixtures/protojson/manifest.json",
  '"schema_package": "reallyme.openid4vci.v1"',
);
requireText(
  "crates/proto-codec/src/json.rs",
  "OPENID4VCI_EMBEDDED_JSON_RECURSION_LIMIT",
);
requireText(
  "crates/proto-codec/src/json.rs",
  "MAX_OPENID4VCI_EMBEDDED_JSON_BYTES",
);
requireText(
  "scripts/proto-hardening/core.mjs",
  "deserialize_zeroizing_bytes",
);
requireText(
  "scripts/proto-hardening/core.mjs",
  "deserialize_zeroizing_string",
);
requireText(
  "scripts/proto-hardening/core.mjs",
  "hardenOneofDeserializers",
);
requireText(
  "scripts/proto-hardening/core.mjs",
  "enforceStrictProtoJson",
);
requireText(
  "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.openid4vci.rs",
  "#[serde(default, deny_unknown_fields)]",
);
requireText(
  "crates/proto-codec/tests/protojson_fixture_tests.rs",
  "fn every_public_generated_message_has_binary_and_protojson_parity",
);
requireText(
  "crates/proto-codec/tests/protojson_fixture_tests.rs",
  "fn protobuf_wire_fixtures_match_protojson_contracts",
);
for (const fuzzSeed of [
  "fuzz/corpus/credential_offer_json/valid.json",
  "fuzz/corpus/issuer_metadata_json/valid.json",
  "fuzz/corpus/issuer_metadata_json/duplicate-configuration-entry.json",
  "fuzz/corpus/credential_request_json/valid.json",
  "fuzz/corpus/credential_response_json/valid.json",
  "fuzz/corpus/deferred_credential_request_json/valid.json",
  "fuzz/corpus/notification_request_json/valid.json",
  "fuzz/corpus/problem_details_json/valid.json",
  "fuzz/corpus/operation_wire/credential-offer-request.json",
  "fuzz/corpus/protojson_messages/operation-request.json",
  "fuzz/corpus/protojson_messages/duplicate-operation-member.json",
]) {
  if (!existsSync(resolve(root, fuzzSeed))) {
    failures.push(`${fuzzSeed}: required generated contract fuzz seed is missing`);
  }
}
requireText(
  "fuzz/fuzz_targets/protojson_messages.rs",
  "pb::OpenId4VciOperationResponse",
);
requireText("fuzz/fuzz_targets/protojson_messages.rs", "json_to_proto");
requireText("fuzz/fuzz_targets/protojson_messages.rs", "proto_to_json");
requireText(
  "crates/proto-codec/tests/roundtrip_tests.rs",
  "fn malformed_protojson_inputs_fail_with_typed_errors",
);
requireText(
  "crates/http/tests/axum_issuer_transport_tests.rs",
  "fn internal_connect_service_is_not_exposed_by_public_router",
);
requireText(
  "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.openid4vci.rs",
  "impl ::core::ops::Drop for Proofs",
);
requireText(
  "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.openid4vci.rs",
  '.field("di_vp_json", &"<redacted>")',
);
requireText(
  "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.openid4vci.__oneof.rs",
  "impl ::core::ops::Drop for Credential",
);
requireText(
  "crates/proto/Cargo.toml",
  '"dep:zeroize"',
);
requireText(
  "crates/proto-codec/src/decode.rs",
  ".with_unknown_field_limit(OPENID4VCI_PROTO_UNKNOWN_FIELD_LIMIT)",
);
requireText(
  "crates/proto-codec/src/decode.rs",
  "decode_proto_with_limit(bytes, MAX_OPENID4VCI_PROTO_MESSAGE_BYTES)",
);
requireText(
  "crates/proto-codec/src/decode.rs",
  ".with_max_message_size(maximum_bytes)",
);
requireText(
  "crates/proto-codec/src/proto_json.rs",
  "pub trait OpenId4VciProtoJson",
);
requireText(
  "crates/proto-codec/src/proto_json.rs",
  "pb::OpenId4VciOperationResponse",
);
const schemaMessages = [
  ...read(messageSchema).matchAll(/^message\s+([A-Za-z][A-Za-z0-9_]*)\s*\{/gmu),
].map((match) => match[1]);
const protoJsonAllowlist = [
  ...read("crates/proto-codec/src/proto_json.rs").matchAll(/\bpb::([A-Za-z][A-Za-z0-9_]*)\b/gu),
].map((match) => match[1]);
const uniqueProtoJsonAllowlist = new Set(protoJsonAllowlist);
for (const message of schemaMessages) {
  if (!uniqueProtoJsonAllowlist.has(message)) {
    failures.push(
      `crates/proto-codec/src/proto_json.rs: generated message ${message} is not classified for ProtoJSON`,
    );
  }
}
for (const message of uniqueProtoJsonAllowlist) {
  if (!schemaMessages.includes(message)) {
    failures.push(
      `crates/proto-codec/src/proto_json.rs: stale ProtoJSON message ${message}`,
    );
  }
}
if (uniqueProtoJsonAllowlist.size !== schemaMessages.length) {
  failures.push(
    "crates/proto-codec/src/proto_json.rs: ProtoJSON allowlist is not a closed-world schema classification",
  );
}
requireText("crates/proto-codec/src/encode.rs", "ProtoCodecResult<Zeroizing<Vec<u8>>>");
requireText("crates/proto-codec/src/encode.rs", "ProtoCodecResult<Zeroizing<String>>");
requireText("crates/proto-codec/src/encode.rs", "M: OpenId4VciProtoJson");
requireText("crates/proto-codec/src/decode.rs", "M: OpenId4VciProtoJson");
requireText("crates/proto-codec/src/encode.rs", "serde_json::to_writer");
requireText("crates/proto-codec/src/encode.rs", "invalid_bytes.zeroize()");
requireText(
  "crates/proto-codec/tests/roundtrip_tests.rs",
  "fn public_generated_encoders_return_zeroizing_owners",
);

const reviewedJsonChokePoints = new Set([
  "crates/proto-codec/src/convert.rs",
  "crates/proto-codec/src/decode.rs",
  "crates/proto-codec/src/encode.rs",
  "crates/proto-codec/src/json.rs",
]);

for (const path of collectRustFiles("crates/proto/src")) {
  if (path.includes("/generated/")) {
    continue;
  }
  rejectText(path, "decode_from_slice(");
  rejectText(path, "serde_json::from_");
  rejectText(path, "serde_json::to_");
}

for (const path of collectRustFiles("crates/proto-codec/src")) {
  if (path !== "crates/proto-codec/src/decode.rs") {
    rejectText(path, "decode_from_slice(");
  }
  if (!reviewedJsonChokePoints.has(path)) {
    rejectText(path, "serde_json::from_");
    rejectText(path, "serde_json::to_");
  }
}

if (failures.length !== 0) {
  console.error("proto-first boundary checks failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("proto-first boundary checks passed");
