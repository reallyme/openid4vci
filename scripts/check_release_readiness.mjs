#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { OPENID4VCI_SCALAR_FIELD_CLASSIFICATIONS } from "./proto-hardening/openid4vci-scalar-policy.mjs";

const coreUrl = process.env.RELEASE_READINESS_CORE_URL;
if (typeof coreUrl !== "string" || coreUrl.length === 0) {
  console.error("release readiness check failed: pinned core URL is unavailable");
  process.exit(1);
}
let releaseReadinessCore;
try {
  const parsedCoreUrl = new URL(coreUrl);
  if (parsedCoreUrl.protocol !== "file:") {
    console.error("release readiness check failed: pinned core URL is invalid");
    process.exit(1);
  }
  releaseReadinessCore = await import(parsedCoreUrl.href);
} catch {
  console.error("release readiness check failed: pinned core URL is invalid");
  process.exit(1);
}
const { createReleaseReadinessContext } = releaseReadinessCore;
if (typeof createReleaseReadinessContext !== "function") {
  console.error("release readiness check failed: pinned core is incomplete");
  process.exit(1);
}

const supportedArguments = new Set(["--generated-freshness", "--policy-only"]);
const suppliedArguments = process.argv.slice(2);
for (const argument of suppliedArguments) {
  if (!supportedArguments.has(argument)) {
    console.error(`release readiness check failed: unsupported argument ${argument}`);
    process.exit(2);
  }
}
if (new Set(suppliedArguments).size !== suppliedArguments.length) {
  console.error("release readiness check failed: duplicate arguments are not allowed");
  process.exit(2);
}
const generatedFreshnessMode = suppliedArguments.includes(
  "--generated-freshness",
);
if (generatedFreshnessMode && suppliedArguments.includes("--policy-only")) {
  console.error(
    "release readiness check failed: generated freshness and policy-only modes are mutually exclusive",
  );
  process.exit(2);
}

const shared = createReleaseReadinessContext({
  scriptUrl: import.meta.url,
  requireTrackedFiles: true,
});

shared.assertReallyMeReleasePackagePolicy({
  scriptPath: "scripts/check_release_readiness.mjs",
  version: "0.6.6",
});
shared.assertWorkflowActionsPinned();
shared.assertNodeWorkflowJobsPinNode({ nodeVersion: "24" });
shared.assertCargoFuzzWorkflowPolicy({
  workflow: ".github/workflows/fuzz.yml",
  version: "0.13.2",
  minimumInstallations: 1,
  requiredInstallSteps: [{ job: "build", name: "Install cargo-fuzz" }],
});
shared.assertCargoWorkspacePolicy();
shared.assertRepositoryShapePolicy({
  archetype: "protocol-engine",
  requiredLanes: [
    "crates",
    "contracts",
    "conformance",
    "docs",
    "scripts",
    ".github",
  ],
  optionalLanes: ["fuzz", "vectors"],
  exceptions: [],
  crates: [
    { path: "crates/openid4vci", role: "facade" },
    { path: "crates/proto", role: "proto" },
    { path: "crates/proto-codec", role: "proto-codec" },
    { path: "crates/types", role: "domain" },
    { path: "crates/issuer", role: "domain" },
    { path: "crates/wallet", role: "domain" },
    { path: "crates/attestation", role: "domain" },
    { path: "crates/profiles", role: "domain" },
    { path: "crates/http", role: "transport" },
  ],
  subLanes: {},
  forbiddenPaths: [
    "COMPLIANCE_MAP.md",
    "CONTRACT.md",
    "JSON_BOUNDARY_INVENTORY.md",
    "PACKAGING_POLICY.md",
    "PROTO_FIRST_REFACTOR_PLAN.md",
    "PROVIDER_POLICY.md",
    "RUST_PACKAGE_POLICY.md",
    "SECURITY.md",
    "SDK_FACADE_INVENTORY.md",
    "SENSITIVE_OWNER_INVENTORY.md",
    "SPEC_MAP.md",
    "THREAT_MODEL.md",
    "TRANSPORT_PARITY.md",
    "ZK_BOUNDARY.md",
    "contracts/COMPLIANCE_MAP.md",
    "contracts/CONTRACT.md",
    "contracts/JSON_BOUNDARY_INVENTORY.md",
    "contracts/PACKAGING_POLICY.md",
    "contracts/PROTO_FIRST_REFACTOR_PLAN.md",
    "contracts/PROVIDER_POLICY.md",
    "contracts/RUST_PACKAGE_POLICY.md",
    "contracts/SDK_FACADE_INVENTORY.md",
    "contracts/SENSITIVE_OWNER_INVENTORY.md",
    "contracts/SPEC_MAP.md",
    "contracts/THREAT_MODEL.md",
    "contracts/TRANSPORT_PARITY.md",
    "contracts/ZK_BOUNDARY.md",
  ],
  requireReleaseReadiness: true,
});
shared.assertRustSourcePolicy({
  roots: ["."],
  generatedPrefixes: ["crates/proto/src/generated"],
  baselinePath: null,
  productionTargetLines: 500,
  productionHardLines: 500,
  testTargetLines: 800,
  testHardLines: 800,
  moduleHardLines: 100,
  forbidWildcardImports: true,
  forbidInlineTests: true,
  forbidSubstantiveFacades: true,
  forbidPanickingProductionCode: true,
  forbidDynamicErrorSurfaces: true,
});
shared.assertSpdxHeaders({
  exclusions: [
    { path: "crates/proto/src/generated", reason: "generated" },
  ],
  requireExclusionsMatched: true,
  requireExclusionReasons: true,
  copyright:
    "SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved",
  license: "SPDX-License-Identifier: MIT OR Apache-2.0",
});

shared.assertReallyMeOperationBoundaryContract({
  protoPath:
    "crates/proto/proto/reallyme/openid4vci/v1/openid4vci.proto",
  operationRequest: "OpenId4VciOperationRequest",
  operationResponse: "OpenId4VciOperationResponse",
  operationResult: "OpenId4VciOperationResult",
  errorMessage: "OpenId4VciOperationError",
  protoReadme: "crates/proto/README.md",
  protoCargo: "crates/proto/Cargo.toml",
  wirePath: "crates/proto-codec/src/operation.rs",
  codecPath: "crates/proto-codec/src/decode.rs",
  processOperationNeedle: "pub fn execute_operation_v1(",
  processOperationJsonNeedle: "pub fn execute_operation_json_v1(",
  binaryResponseNeedle: "decode_proto_with_limit",
  requiredCodecNeedles: [
    ".with_recursion_limit(OPENID4VCI_PROTO_RECURSION_LIMIT)",
    ".with_unknown_field_limit(OPENID4VCI_PROTO_UNKNOWN_FIELD_LIMIT)",
    ".with_max_message_size(maximum_bytes)",
  ],
  forbiddenCodecNeedles: ["serde_json::Value"],
  sdkAdapters: [],
  allowServices: false,
});

const generatedBuffaFiles = [
  "crates/proto/src/generated/buffa/mod.rs",
  "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.mod.rs",
  "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.openid4vci.rs",
  "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.openid4vci.__oneof.rs",
  "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.openid4vci.__view.rs",
  "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.openid4vci.__view_oneof.rs",
];

shared.assertReallyMeProtobufReleasePolicy({
  corePath: "scripts/check_release_readiness.mjs",
  buffaVersion: "0.9.2",
  generatedFreshnessMode,
  workflowMode: "delegated",
  generatedFreshnessStepRun:
    "node .release-readiness/scripts/run-consumer-check.mjs --generated-freshness",
  installBufUses:
    "bufbuild/buf-setup-action@a47c93e0b1648d5651a065437926377d060baa99",
  hardeningPolicy: {
    hardeningScript: "scripts/proto-hardening/core.mjs",
    protoSchema:
      "crates/proto/proto/reallyme/openid4vci/v1/openid4vci.proto",
    generatedRust:
      "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.openid4vci.rs",
    generatedView:
      "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.openid4vci.__view.rs",
    protoCargo: "crates/proto/Cargo.toml",
    requiredScriptNeedles: [
      "parseProtoContracts",
      "deserialize_zeroizing_bytes",
      "deserialize_zeroizing_string",
      "hardenOneofDeserializers",
      "hardenOneofs",
      "hardenViewOneofs",
      "scalarFieldClassifications",
    ],
    requiredCargoNeedles: ['"dep:zeroize"'],
    scalarFieldClassifications: OPENID4VCI_SCALAR_FIELD_CLASSIFICATIONS,
    requiredGeneratedNeedles: [
      "deserialize_zeroizing_bytes",
      "deserialize_zeroizing_string",
      "impl ::core::ops::Drop for Proofs",
      "__reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);",
    ],
    forbiddenGeneratedNeedles: [
      '.field("di_vp_json", &self.di_vp_json)',
      '.field("jwt", &self.jwt)',
      "::buffa::alloc::format!(",
    ],
    requiredViewNeedles: [
      'formatter.write_str("ProofsView(<redacted>)")',
      'formatter.write_str("ProofsOwnedView(<redacted>)")',
    ],
    additionalGeneratedPolicies: [
      {
        path:
          "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.openid4vci.__oneof.rs",
        required: [
          'formatter.write_str("Credential::Json(<redacted>)")',
          "impl ::core::ops::Drop for Credential",
          "Self::Json(value) => ::zeroize::Zeroize::zeroize(value)",
        ],
      },
      {
        path:
          "crates/proto/src/generated/buffa/reallyme.openid4vci.v1.openid4vci.__view_oneof.rs",
        required: ['formatter.write_str("CredentialView::Json(<redacted>)")'],
      },
      {
        path: "crates/proto/tests/generated_security_tests.rs",
        required: [
          "generated_proof_debug_output_is_redacted",
          "generated_credential_oneof_debug_output_is_redacted",
          "generated_clear_zeroizes_sensitive_fields",
        ],
      },
    ],
  },
  generatedFreshness: {
    generatedPaths: ["crates/proto/src/generated/buffa"],
    commands: [
      ["buf", ["lint"]],
      ["scripts/regenerate-openid4vci-proto.sh", []],
    ],
  },
});

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

function assertNoDocumentationSpdxHeaders() {
  const tracked = spawnSync(
    "git",
    ["ls-files", "-z", "--", "*.md", "*.txt"],
    { cwd: root, encoding: "utf8" },
  );
  if (tracked.status !== 0) {
    console.error(
      "release readiness check failed: unable to enumerate tracked documentation",
    );
    process.exit(1);
  }
  for (const path of tracked.stdout.split("\0").filter(Boolean)) {
    if (!existsSync(resolve(root, path))) {
      continue;
    }
    const source = readFileSync(resolve(root, path), "utf8");
    if (
      source.includes("SPDX-FileCopyrightText:") ||
      source.includes("SPDX-License-Identifier:")
    ) {
      console.error(
        `release readiness check failed: ${path} must not carry an SPDX header`,
      );
      process.exit(1);
    }
  }
}

assertNoDocumentationSpdxHeaders();
const readText = (path) => readFileSync(resolve(root, path), "utf8");

function fail(message) {
  console.error(`release readiness check failed: ${message}`);
  process.exit(1);
}

function assertExists(path) {
  if (!existsSync(resolve(root, path))) {
    fail(`${path} is missing`);
  }
}

function assertAbsent(path) {
  if (existsSync(resolve(root, path))) {
    fail(`${path} must not be checked in`);
  }
}

function assertContains(path, needle) {
  if (!readText(path).includes(needle)) {
    fail(`${path} does not contain ${needle}`);
  }
}

function assertNotContains(path, needle) {
  if (readText(path).includes(needle)) {
    fail(`${path} still contains ${needle}`);
  }
}

function workflowJobLines(path, jobName) {
  const lines = readText(path).split(/\r?\n/u);
  const jobHeader = `  ${jobName}:`;
  const start = lines.findIndex((line) => line === jobHeader);
  if (start < 0) {
    fail(`${path} has no ${jobName} job`);
  }
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^  [A-Za-z0-9_-]+:$/u.test(lines[index])) {
      end = index;
      break;
    }
  }
  return lines.slice(start + 1, end);
}

function assertWorkflowJobScalar(path, jobName, key, expected) {
  const exact = `    ${key}: ${expected}`;
  const matches = workflowJobLines(path, jobName).filter((line) => line === exact);
  if (matches.length !== 1) {
    fail(`${path} ${jobName} job must contain exactly one ${key}: ${expected}`);
  }
}

function assertWorkflowJobPermission(path, jobName, permission, expected) {
  const lines = workflowJobLines(path, jobName);
  const permissionsIndex = lines.findIndex((line) => line === "    permissions:");
  if (permissionsIndex < 0) {
    fail(`${path} ${jobName} job has no permissions mapping`);
  }
  const exact = `      ${permission}: ${expected}`;
  const permissionLines = [];
  for (let index = permissionsIndex + 1; index < lines.length; index += 1) {
    if (!lines[index].startsWith("      ")) {
      break;
    }
    permissionLines.push(lines[index]);
  }
  if (permissionLines.filter((line) => line === exact).length !== 1) {
    fail(`${path} ${jobName} permissions must contain exactly one ${permission}: ${expected}`);
  }
}

function assertWorkflowJobNotContains(path, jobName, needle) {
  if (workflowJobLines(path, jobName).some((line) => line.includes(needle))) {
    fail(`${path} ${jobName} job must not contain ${needle}`);
  }
}

function assertWorkflowJobContains(path, jobName, needle) {
  if (!workflowJobLines(path, jobName).some((line) => line.includes(needle))) {
    fail(`${path} ${jobName} job must contain ${needle}`);
  }
}

for (const path of [
  "README.md",
  "conformance/README.md",
  "crates/proto/README.md",
  "crates/types/README.md",
  "crates/wallet/README.md",
  "docs/SECURITY.md",
  "docs/THREAT_MODEL.md",
  "docs/TRUST_EVIDENCE_PROFILE.md",
  "vectors/README.md",
  "crates/openid4vci/Cargo.toml",
  "crates/proto/Cargo.toml",
  "crates/proto-codec/Cargo.toml",
  "crates/wallet/Cargo.toml",
  "scripts/check-rust-source-policy.sh",
  "scripts/test-policy-tool-failures.sh",
  "scripts/check-ssi-remote-resolution.mjs",
  "crates/proto/proto/reallyme/openid4vci/v1/openid4vci.proto",
  "crates/proto/proto/reallyme/openid4vci/v1/openid4vci_service.proto",
  "LICENSE-MIT",
  "LICENSE-APACHE",
  "crates/proto/LICENSE-MIT",
  "crates/proto/LICENSE-APACHE",
  "crates/types/LICENSE-MIT",
  "crates/types/LICENSE-APACHE",
  "crates/wallet/LICENSE-MIT",
  "crates/wallet/LICENSE-APACHE",
  "conformance/fixtures/oidf/openid4vci-conformance-mdoc-iaca.pem",
  "scripts/check-proto-first-boundaries.mjs",
  "scripts/check-openid4vci-format.sh",
  "scripts/check-published-semver.mjs",
  "scripts/check-published-semver.test.mjs",
  "scripts/publish-crates-in-order.mjs",
  "scripts/publish-crates-in-order.test.mjs",
  "scripts/verify_release_source.mjs",
  "scripts/verify_release_source.test.mjs",
  "scripts/verify_required_ci.mjs",
  "scripts/verify_required_ci.test.mjs",
  "scripts/verify_release_attestation.mjs",
  "scripts/verify_release_attestation.test.mjs",
  "scripts/write_release_attestation.mjs",
  "scripts/audit_committed_lockfiles.sh",
  "scripts/run-gitleaks.sh",
  "scripts/harden-generated-openid4vci-proto.mjs",
  "scripts/proto-hardening/core.mjs",
  "scripts/proto-hardening/openid4vci-scalar-policy.mjs",
  "scripts/regenerate-openid4vci-proto.sh",
  ".github/workflows/protobuf-ci.yml",
  ".github/workflows/crates-package-preflight.yml",
  ".github/workflows/crates-release.yml",
  ".github/workflows/secret-scan.yml",
  "fuzz/corpus/credential_offer_json/valid.json",
  "fuzz/corpus/credential_request_json/valid.json",
  "fuzz/corpus/credential_response_json/valid.json",
  "fuzz/corpus/deferred_credential_request_json/valid.json",
  "fuzz/corpus/issuer_metadata_json/valid.json",
  "fuzz/corpus/issuer_metadata_json/duplicate-configuration-entry.json",
  "fuzz/corpus/notification_request_json/valid.json",
  "fuzz/corpus/operation_wire/credential-offer-request.json",
  "fuzz/corpus/problem_details_json/valid.json",
  "fuzz/corpus/protojson_messages/operation-request.json",
  "fuzz/corpus/protojson_messages/duplicate-operation-member.json",
  "vectors/README.md",
  "vectors/openid4vci-final-negative.json",
  "vectors/openid4vci-jwe.json",
]) {
  assertExists(path);
}

for (const path of [
  "protos/reallyme/openid4vci/v1/openid4vci.proto",
  "crates/holder",
  "crates/proto/openid4vci",
  "crates/proto/codec",
  "crates/proto/src/generated/connect",
  "crates/ffi",
  "crates/jni",
  "crates/wasm",
  "packages",
  "packages/android",
  "packages/kotlin",
  "packages/kotlin-android",
  "packages/swift",
  "packages/ts",
  "packages/typescript",
  "packages/wasm",
  ".github/workflows/android-package-preflight.yml",
  ".github/workflows/jvm-package-preflight.yml",
  ".github/workflows/npm-package-preflight.yml",
  ".github/workflows/swift-package-preflight.yml",
  ".github/workflows/xcframework-package-preflight.yml",
]) {
  assertAbsent(path);
}

assertNotContains("Cargo.toml", "connectrpc");
assertNotContains("Cargo.toml", '"crates/wasm"');
assertNotContains("buf.gen.yaml", "protoc-gen-connect");
assertNotContains("buf.gen.yaml", "bufbuild/es");
assertNotContains("crates/proto-codec/src/operation.rs", "process_proto(");
assertNotContains(
  "crates/proto/proto/reallyme/openid4vci/v1/openid4vci.proto",
  "CodecProtoResultEnvelope",
);
assertNotContains(
  "crates/proto/proto/reallyme/openid4vci/v1/openid4vci.proto",
  "service OpenId4VciIssuerService",
);
assertContains(
  "crates/proto/proto/reallyme/openid4vci/v1/openid4vci_service.proto",
  "service OpenId4VciIssuerService",
);
assertContains("crates/proto/Cargo.toml", '"/proto/**/*.proto"');
assertContains("crates/proto/Cargo.toml", '"/tests/**/*"');
assertContains(
  "crates/proto-codec/tests/protojson_fixture_tests.rs",
  "protobuf_wire_fixtures_match_protojson_contracts",
);
assertContains(
  "crates/proto-codec/src/proto_json.rs",
  "pub trait OpenId4VciProtoJson",
);
assertContains(
  "crates/proto-codec/src/encode.rs",
  "ProtoCodecResult<Zeroizing<String>>",
);
assertContains(
  "crates/proto-codec/src/encode.rs",
  "ProtoCodecResult<Zeroizing<Vec<u8>>>",
);
assertContains("Cargo.toml", 'license = "MIT OR Apache-2.0"');
assertContains("README.md", "[MIT License](LICENSE-MIT)");
assertContains("README.md", "[Apache License, Version 2.0](LICENSE-APACHE)");
assertContains(
  "README.md",
  "git -C .release-readiness checkout --detach bdedc88f3f25fcc14242730d4dec6ce6a0c75531",
);
assertContains("README.md", "node .release-readiness/scripts/run-consumer-check.mjs");
assertContains(".gitignore", "!crates/proto/src/generated/**");
assertContains(".gitignore", "/.release-readiness/");
assertContains(".github/workflows/rust-ci.yml", "scripts/check-openid4vci-format.sh");
assertContains(".github/workflows/rust-ci.yml", "scripts/check-rust-source-policy.sh");
assertContains(".github/workflows/rust-ci.yml", "tool: ripgrep@15.2.0");
assertContains(".github/workflows/rust-ci.yml", "CARGO_SEMVER_CHECKS_VERSION: 0.50.0");
assertContains(
  ".github/workflows/rust-ci.yml",
  "cargo-semver-checks@${{ env.CARGO_SEMVER_CHECKS_VERSION }}",
);
assertContains(".github/workflows/rust-ci.yml", "node scripts/check-published-semver.mjs");
assertContains(".github/workflows/rust-ci.yml", "scripts/test-policy-tool-failures.sh");
assertContains(
  ".github/workflows/rust-ci.yml",
  "node scripts/check-ssi-remote-resolution.mjs",
);
assertContains(
  ".github/workflows/rust-ci.yml",
  "node --test scripts/*.test.mjs",
);
assertContains(
  ".github/workflows/rust-ci.yml",
  "python3 -m unittest discover -s scripts/conformance -p 'test_*.py'",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "node scripts/publish-crates-in-order.mjs inspect",
);
assertContains("scripts/publish-crates-in-order.mjs", '"--locked"');
assertContains("fuzz/Cargo.toml", 'name = "operation_wire"');
assertContains("fuzz/Cargo.toml", 'name = "protojson_messages"');
assertContains(".github/workflows/fuzz.yml", "operation_wire");
assertContains(".github/workflows/fuzz.yml", "protojson_messages");
assertContains(".github/workflows/fuzz.yml", '      - "!**/*.md"');
assertContains(
  ".github/workflows/fuzz.yml",
  'push:\n    branches:\n      - main\n    # Release preflight still requires successful exact-commit evidence. Manually\n    # dispatch this workflow when a Markdown-only HEAD is a release candidate.\n    paths-ignore:\n      - "**/*.md"',
);
assertContains(
  ".github/workflows/fuzz.yml",
  "cargo +nightly-2026-09-15 metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1 --no-deps",
);
assertNotContains(
  ".github/workflows/fuzz.yml",
  "cargo +nightly-2026-09-15 fuzz build --locked",
);
assertNotContains(".github/workflows/protobuf-ci.yml", '      - "!**/*.md"');
assertContains(".github/workflows/rust-ci.yml", '      - "**/*.md"');
assertContains(
  ".github/workflows/rust-ci.yml",
  'push:\n    branches:\n      - main\n    # Release preflight still requires successful exact-commit evidence. Manually\n    # dispatch this workflow when a Markdown-only HEAD is a release candidate.\n    paths-ignore:\n      - "**/*.md"',
);
assertContains(
  ".github/workflows/protobuf-ci.yml",
  'push:\n    branches:\n      - main\n      - trunk\n    # Release preflight still requires successful exact-commit evidence. Manually\n    # dispatch this workflow when a Markdown-only HEAD is a release candidate.\n    paths-ignore:\n      - "**/*.md"',
);
assertContains(".github/workflows/rust-ci.yml", "workflow_dispatch:");
assertContains(".github/workflows/rust-ci.yml", "CARGO_AUDIT_VERSION: 0.22.2");
assertContains(".github/workflows/rust-ci.yml", "CARGO_DENY_VERSION: 0.20.2");
for (const workflow of [
  ".github/workflows/rust-ci.yml",
  ".github/workflows/fuzz.yml",
  ".github/workflows/oidf-conformance.yml",
  ".github/workflows/protobuf-ci.yml",
  ".github/workflows/crates-package-preflight.yml",
  ".github/workflows/crates-release.yml",
  ".github/workflows/secret-scan.yml",
]) {
  assertNotContains(workflow, "REALLYME_REPO_READ_TOKEN");
  assertNotContains(workflow, "repository: reallyme/ssi");
  assertNotContains(workflow, "path: ssi");
}
assertContains(".github/workflows/protobuf-ci.yml", "path: openid4vci");
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "working-directory: openid4vci",
);
assertContains(".github/workflows/protobuf-ci.yml", "github_token: ${{ github.token }}");
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "buf format --diff --exit-code crates/proto/proto",
);
assertContains(
  ".github/workflows/protobuf-ci.yml",
  'buf breaking --against "https://github.com/${GITHUB_REPOSITORY}.git#branch=${{ github.event.repository.default_branch }}"',
);
assertNotContains(".github/workflows/rust-ci.yml", "cargo install cargo-audit");
assertNotContains(".github/workflows/rust-ci.yml", "cargo install cargo-deny");
assertNotContains(
  ".github/workflows/crates-package-preflight.yml",
  "go run github.com/bufbuild/buf",
);
assertAbsent(".github/workflows/release-preflight.yml");
assertAbsent("conformance/fixtures/oidf/reallyme-identity-v1-mdoc-iaca.pem");
for (const readme of [
  "crates/proto/README.md",
  "crates/types/README.md",
  "crates/attestation/README.md",
  "crates/wallet/README.md",
  "crates/profiles/README.md",
  "crates/issuer/README.md",
  "crates/proto-codec/README.md",
  "crates/http/README.md",
  "crates/openid4vci/README.md",
]) {
  assertNotContains(readme, "not yet available from crates.io");
}
assertContains("crates/wallet/Cargo.toml", 'documentation = "https://docs.rs/reallyme-openid4vci-wallet"');
assertContains("crates/wallet/Cargo.toml", '"/LICENSE-MIT"');
assertContains("crates/wallet/Cargo.toml", '"/LICENSE-APACHE"');
assertNotContains("crates/http/examples/issuer/mdoc.rs", "ReallyMe Identity v1.0");
assertNotContains("conformance/eudi/sources.lock", "launch certification claims");
assertNotContains("scripts/publish-crates-in-order.mjs", "OIDC token");

const packagePreflightWorkflow = ".github/workflows/crates-package-preflight.yml";
const cratesReleaseWorkflow = ".github/workflows/crates-release.yml";
const rustCiWorkflow = ".github/workflows/rust-ci.yml";
const fuzzCiWorkflow = ".github/workflows/fuzz.yml";
const oidfWorkflow = ".github/workflows/oidf-conformance.yml";
const protobufWorkflow = ".github/workflows/protobuf-ci.yml";
const workflowFiles = [
  rustCiWorkflow,
  fuzzCiWorkflow,
  oidfWorkflow,
  protobufWorkflow,
  packagePreflightWorkflow,
  cratesReleaseWorkflow,
  ".github/workflows/repository-security.yml",
  ".github/workflows/secret-scan.yml",
];

for (const action of [
  "actions/checkout",
  "actions/setup-node",
  "actions/upload-artifact",
  "actions/download-artifact",
  "actions/attest-build-provenance",
  "dtolnay/rust-toolchain",
  "Swatinem/rust-cache",
  "taiki-e/install-action",
]) {
  const pins = new Set();
  const expression = new RegExp(`${action.replace("/", "\\/")}@([0-9a-f]{40})`, "gu");
  for (const workflow of workflowFiles) {
    for (const match of readText(workflow).matchAll(expression)) {
      pins.add(match[1]);
    }
  }
  if (pins.size > 1) {
    fail(`${action} uses inconsistent workflow pins`);
  }
}

const renovateConfig = JSON.parse(readText(".github/renovate.json"));
if (
  !Array.isArray(renovateConfig.extends) ||
  !renovateConfig.extends.includes("helpers:pinGitHubActionDigests")
) {
  fail("Renovate must pin GitHub Action digests");
}
if (renovateConfig.minimumReleaseAge !== "7 days") {
  fail("Renovate must enforce the dependency release cooling-off period");
}
const requiredGroupedSsiPackages = [
  "reallyme-mdoc",
  "reallyme-openid-oauth",
  "reallyme-openid4vc-profiles",
  "reallyme-revocation",
  "reallyme-ssi-proto",
  "reallyme-trust-core",
  "reallyme-trust-x509",
];
const groupedSsiRule = renovateConfig.packageRules?.find(
  (rule) => rule.groupName === "Published ReallyMe SSI crates",
);
if (
  groupedSsiRule === undefined ||
  !Array.isArray(groupedSsiRule.matchPackageNames) ||
  requiredGroupedSsiPackages.some(
    (packageName) => !groupedSsiRule.matchPackageNames.includes(packageName),
  )
) {
  fail("Renovate must update every direct SSI-family dependency as one group");
}

assertContains("Cargo.toml", 'rust-version = "1.96"');
assertContains("rust-toolchain.toml", 'channel = "1.98.1"');
for (const workflow of [
  rustCiWorkflow,
  protobufWorkflow,
  oidfWorkflow,
  packagePreflightWorkflow,
  cratesReleaseWorkflow,
]) {
  assertContains(workflow, "toolchain: 1.98.1");
}
assertContains(
  rustCiWorkflow,
  "cargo nextest run --locked --workspace --no-default-features --features native",
);
assertContains(
  rustCiWorkflow,
  "cargo nextest run --locked --workspace --all-features",
);
assertContains(
  rustCiWorkflow,
  "cargo doc --locked --workspace --no-deps --all-features",
);
assertContains(rustCiWorkflow, "scripts/audit_committed_lockfiles.sh");
assertWorkflowJobContains(rustCiWorkflow, "msrv", "toolchain: 1.96.0");
assertWorkflowJobContains(rustCiWorkflow, "msrv", "cargo +1.96.0 check --locked");
assertContains(rustCiWorkflow, "cargo deny --locked check");
assertContains(
  rustCiWorkflow,
  "cargo deny --locked --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check",
);
assertContains(protobufWorkflow, "cache-bin: false");
assertNotContains(oidfWorkflow, "workflow_call:");
assertContains(oidfWorkflow, "workflow_dispatch:");
assertContains(oidfWorkflow, "maven@sha256:");
assertContains(oidfWorkflow, '-e HOME=/maven-home');
assertContains(oidfWorkflow, '-e MAVEN_CONFIG=/maven-home');
assertContains(oidfWorkflow, '-v "${maven_home}:/maven-home"');
assertContains(
  oidfWorkflow,
  "-Dmaven.repo.local=/maven-home/repository",
);
assertContains(oidfWorkflow, "-Dmaven.test.skip -Dpmd.skip clean package");
assertContains(oidfWorkflow, "FROM eclipse-temurin@sha256:");
assertContains(
  oidfWorkflow,
  "apt-get install --yes --no-install-recommends redir \\&\\& rm -rf /var/lib/apt/lists/\\*",
);
assertContains(oidfWorkflow, "FROM nginx@sha256:");
assertWorkflowJobContains(
  rustCiWorkflow,
  "msrv",
  "-p reallyme-openid4vci-types",
);
assertWorkflowJobContains(
  rustCiWorkflow,
  "msrv",
  "-p reallyme-openid4vci-proto",
);
assertWorkflowJobContains(
  rustCiWorkflow,
  "msrv",
  "-p reallyme-openid4vci-wallet",
);
for (const packageName of [
  "openid4vci-attestation",
  "openid4vci-profiles",
  "openid4vci-issuer",
  "openid4vci-proto-codec",
  "openid4vci-http",
  "reallyme-openid4vci",
]) {
  assertWorkflowJobContains(rustCiWorkflow, "msrv", `-p ${packageName}`);
}
const releaseVersionMatch = readText("crates/proto/Cargo.toml").match(
  /^version = "([^"]+)"$/m,
);
if (releaseVersionMatch?.[1] === undefined) {
  fail("crates/proto/Cargo.toml has no unambiguous package version");
}

assertContains(packagePreflightWorkflow, "name: Crates Package Preflight");
assertContains(
  packagePreflightWorkflow,
  "run-name: Crates package preflight ${{ inputs.version }} @ ${{ github.sha }}",
);
assertContains(packagePreflightWorkflow, `default: ${releaseVersionMatch[1]}`);
assertContains(
  packagePreflightWorkflow,
  "group: crates-package-preflight-${{ inputs.version }}-${{ github.sha }}",
);
assertContains(packagePreflightWorkflow, "runs-on: ubuntu-24.04");
assertContains(packagePreflightWorkflow, "ref: ${{ github.sha }}");
assertContains(packagePreflightWorkflow, "fetch-depth: 0");
assertContains(packagePreflightWorkflow, "persist-credentials: false");
assertContains(packagePreflightWorkflow, "node scripts/verify_release_source.mjs");
assertWorkflowJobScalar(packagePreflightWorkflow, "verify-source-sha", "timeout-minutes", "90");
assertContains(packagePreflightWorkflow, "node scripts/verify_required_ci.mjs");
assertContains(packagePreflightWorkflow, "REQUIRED_CI_WAIT_SECONDS: '3600'");
assertContains(packagePreflightWorkflow, "REQUIRED_CI_POLL_SECONDS: '60'");
assertContains(packagePreflightWorkflow, "REQUIRED_CI_WRITE_GITHUB_OUTPUT: '1'");
assertNotContains(packagePreflightWorkflow, "gh run list");
assertContains("scripts/verify_required_ci.mjs", 'workflowFile: "rust-ci.yml"');
assertContains("scripts/verify_required_ci.mjs", 'workflowFile: "protobuf-ci.yml"');
assertContains("scripts/verify_required_ci.mjs", 'workflowFile: "fuzz.yml"');
assertNotContains("scripts/verify_required_ci.mjs", 'workflowFile: "oidf-conformance.yml"');
assertContains(
  "scripts/verify_required_ci.mjs",
  'error.code.startsWith("required-ci-run-pending:")',
);
assertContains(
  "scripts/verify_required_ci.mjs",
  'error.code.startsWith("missing-required-ci-run:")',
);
assertContains(packagePreflightWorkflow, "node scripts/write_release_attestation.mjs");
assertNotContains(packagePreflightWorkflow, "oidf-conformance:");
assertNotContains(packagePreflightWorkflow, "OIDF_CONFORMANCE_RUN_ID");
assertContains(packagePreflightWorkflow, "attest-reviewed-evidence:");
assertWorkflowJobContains(
  packagePreflightWorkflow,
  "attest-reviewed-evidence",
  "needs: [verify-source-sha, crates-package]",
);
assertWorkflowJobContains(
  packagePreflightWorkflow,
  "attest-reviewed-evidence",
  "actions/attest-build-provenance@",
);
assertWorkflowJobContains(
  packagePreflightWorkflow,
  "attest-reviewed-evidence",
  "id-token: write",
);
assertContains(
  packagePreflightWorkflow,
  "reallyme-openid4vci-crates-preflight-${{ inputs.version }}-${{ github.sha }}",
);
assertContains(packagePreflightWorkflow, "scripts/run-gitleaks.sh");
assertContains(packagePreflightWorkflow, "scripts/audit_committed_lockfiles.sh");
assertContains(
  packagePreflightWorkflow,
  "node .release-readiness/scripts/run-consumer-check.mjs",
);
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "node .release-readiness/scripts/run-consumer-check.mjs --generated-freshness",
);
assertContains(
  ".github/workflows/rust-ci.yml",
  "node .release-readiness/scripts/run-consumer-check.mjs --policy-only",
);
for (const releaseReadinessWorkflow of [
  packagePreflightWorkflow,
  ".github/workflows/protobuf-ci.yml",
  ".github/workflows/rust-ci.yml",
]) {
  assertContains(releaseReadinessWorkflow, "repository: reallyme/release-readiness");
  assertContains(
    releaseReadinessWorkflow,
    "ref: bdedc88f3f25fcc14242730d4dec6ce6a0c75531",
  );
  assertContains(releaseReadinessWorkflow, "persist-credentials: false");
  assertNotContains(releaseReadinessWorkflow, "npm exec --yes --package=github:");
}
assertContains(packagePreflightWorkflow, "cargo-audit@${{ env.CARGO_AUDIT_VERSION }}");
assertNotContains(packagePreflightWorkflow, "https://crates.io/api/");
assertNotContains(packagePreflightWorkflow, "cargo-semver-checks");
assertNotContains(packagePreflightWorkflow, "semver-checks");
assertContains(".github/workflows/secret-scan.yml", "fetch-depth: 0");
assertContains(".github/workflows/secret-scan.yml", "scripts/run-gitleaks.sh");
assertNotContains(".github/workflows/secret-scan.yml", "paths-ignore:");
assertContains(
  ".github/workflows/repository-security.yml",
  "private-vulnerability-reporting",
);
assertContains("scripts/run-gitleaks.sh", 'readonly GITLEAKS_VERSION="8.30.1"');
assertContains("scripts/run-gitleaks.sh", "gitleaks archive digest mismatch");
assertContains("scripts/run-gitleaks.sh", '"${binary_path}" git --redact --no-banner --verbose .');

// General CI owns compilation and test validation. Package preflight reruns
// release policy, history secret scanning, and advisory checks against the
// exact release commit without rebuilding the workspace.
for (const duplicate of [
  "scripts/check-openid4vci-format.sh",
  "scripts/check-rust-source-policy.sh",
  "cargo clippy",
  "cargo test --locked --workspace",
  "scripts/run-fuzz-smoke.sh",
  "cargo deny",
  "buf lint",
]) {
  assertNotContains(packagePreflightWorkflow, duplicate);
}
for (const duplicate of [
  "cargo check --locked --workspace --all-features",
  "cargo test --locked -p openid4vci-http --example issuer",
  "scripts/run-fuzz-smoke.sh",
  "node scripts/publish-crates-in-order.mjs inspect",
]) {
  assertNotContains(rustCiWorkflow, duplicate);
}
assertContains(fuzzCiWorkflow, "needs: build");
assertContains(fuzzCiWorkflow, "fuzz-executables-${{ github.sha }}");
assertWorkflowJobNotContains(fuzzCiWorkflow, "scheduled", "cargo fuzz");
assertWorkflowJobNotContains(fuzzCiWorkflow, "scheduled", "Install Rust nightly");
assertContains(oidfWorkflow, "prepare-oidf-assets:");
assertWorkflowJobNotContains(oidfWorkflow, "oid4vci-issuer", "cargo build");
assertWorkflowJobNotContains(oidfWorkflow, "oid4vci-issuer", "mvn -q");

assertContains(cratesReleaseWorkflow, "name: Crates.io Release");
assertContains(cratesReleaseWorkflow, "run-name: Crates.io release @ ${{ github.sha }}");
assertContains(cratesReleaseWorkflow, "workflow_dispatch:");
assertNotContains(cratesReleaseWorkflow, "${{ inputs.");
assertContains(cratesReleaseWorkflow, "if: github.ref == 'refs/heads/main'");
assertContains(cratesReleaseWorkflow, "actions: read");
assertContains(cratesReleaseWorkflow, "RELEASE_SOURCE_DERIVE_VERSION: '1'");
assertContains(cratesReleaseWorkflow, "RELEASE_ATTESTATION_RESOLVE_ONLY: '1'");
assertContains(cratesReleaseWorkflow, "node scripts/verify_release_attestation.mjs");
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "publish",
  "uses: actions/download-artifact@",
);
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "publish",
  "node scripts/verify_release_attestation.mjs",
);
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "verify-preflight",
  "gh attestation verify",
);
assertWorkflowJobScalar(cratesReleaseWorkflow, "verify-preflight", "timeout-minutes", "90");
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "publish",
  "needs: [verify-preflight, prepare-source-release]",
);
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "prepare-source-release",
  "Create or verify immutable release tag",
);
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "prepare-source-release",
  "--draft",
);
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "prepare-source-release",
  '--target "$RELEASE_SHA"',
);
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "finalize",
  "needs: [verify-preflight, prepare-source-release, publish]",
);
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "finalize",
  "gh release edit",
);
assertWorkflowJobContains(cratesReleaseWorkflow, "finalize", "--draft=false");
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "finalize",
  "reallyme-openid4vci-crate-archives-",
);
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "verify-preflight",
  'test "$archive_count" -eq 9',
);
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "finalize",
  '"reallyme-openid4vci-wallet-${RELEASE_VERSION}.crate"',
);
for (const packageName of [
  "reallyme-openid4vci-proto",
  "reallyme-openid4vci-types",
  "openid4vci-attestation",
  "openid4vci-profiles",
  "openid4vci-issuer",
  "openid4vci-proto-codec",
  "openid4vci-http",
  "reallyme-openid4vci",
]) {
  assertWorkflowJobContains(
    cratesReleaseWorkflow,
    "finalize",
    `"${packageName}-\${RELEASE_VERSION}.crate"`,
  );
}
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "finalize",
  "is already public but is missing",
);
assertContains(
  cratesReleaseWorkflow,
  "CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}",
);
assertWorkflowJobScalar(cratesReleaseWorkflow, "publish", "environment", "crates-io");
assertWorkflowJobScalar(cratesReleaseWorkflow, "publish", "timeout-minutes", "120");
assertWorkflowJobNotContains(cratesReleaseWorkflow, "publish", "id-token:");
assertWorkflowJobNotContains(cratesReleaseWorkflow, "publish", "rust-cache");
assertWorkflowJobNotContains(
  cratesReleaseWorkflow,
  "publish",
  "uses: rust-lang/crates-io-auth-action@",
);
assertWorkflowJobContains(
  cratesReleaseWorkflow,
  "publish",
  'if [ -z "${CARGO_REGISTRY_TOKEN}" ]; then',
);
assertContains(cratesReleaseWorkflow, "node scripts/publish-crates-in-order.mjs publish");
assertContains(cratesReleaseWorkflow, "PUBLICATION_LEDGER_PATH:");
assertContains(cratesReleaseWorkflow, "reallyme-openid4vci-publication-ledger-");
assertContains(cratesReleaseWorkflow, 'tag="reallyme-openid4vci-v${RELEASE_VERSION}"');
assertContains(
  cratesReleaseWorkflow,
  'gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs"',
);
assertNotContains(cratesReleaseWorkflow, "git push");
assertContains(cratesReleaseWorkflow, "gh release create");
assertNotContains(cratesReleaseWorkflow, "--generate-notes");
assertContains("scripts/publish-crates-in-order.mjs", 'const MODE_ORDER = "order";');
assertContains("scripts/publish-crates-in-order.mjs", '"release-preflight-target"');
assertContains("scripts/publish-crates-in-order.mjs", '"--no-verify"');
assertContains("scripts/publish-crates-in-order.mjs", "verifyPublishedPackageMatches(pkg)");
assertContains("scripts/publish-crates-in-order.mjs", "APPROVED_PUBLIC_PACKAGES");
assertContains("scripts/publish-crates-in-order.mjs", "retryAfterMs");
assertContains("scripts/publish-crates-in-order.mjs", "/\\b429\\b/u");
assertContains(
  "scripts/publish-crates-in-order.mjs",
  'combined.includes("failed to select a version for the requirement")',
);
assertContains("scripts/verify_release_source.mjs", "main:refs/remotes/origin/main");
for (const manifest of [
  "crates/proto/Cargo.toml",
  "crates/types/Cargo.toml",
  "crates/attestation/Cargo.toml",
  "crates/wallet/Cargo.toml",
  "crates/profiles/Cargo.toml",
  "crates/issuer/Cargo.toml",
  "crates/proto-codec/Cargo.toml",
  "crates/http/Cargo.toml",
  "crates/openid4vci/Cargo.toml",
]) {
  assertContains("scripts/verify_release_source.mjs", `"${manifest}"`);
}
assertContains("scripts/verify_release_attestation.mjs", "value.run_attempt !== 1");
assertContains("scripts/verify_release_attestation.mjs", "preflight-run-id-changed");
assertContains(
  "scripts/verify_release_attestation.mjs",
  "verifyAttestedCrateArchives",
);
assertContains(
  "scripts/write_release_attestation.mjs",
  "reallyme.openid4vci.crates_preflight.v5",
);
assertContains(
  "scripts/publish-crates-in-order.mjs",
  "reallyme.openid4vci.crates-publication-ledger.v1",
);
assertContains("scripts/run-fuzz-smoke.sh", 'fuzz_args+=("$corpus_dir")');
assertContains("fuzz/Cargo.toml", 'non_kebab_case_bins = "allow"');
assertContains("fuzz/.gitignore", "!corpus/operation_wire/");

const fuzzCargo = readText("fuzz/Cargo.toml");
const fuzzSmoke = readText("scripts/run-fuzz-smoke.sh");
const fuzzWorkflow = readText(".github/workflows/fuzz.yml");
const fuzzTargets = [...fuzzCargo.matchAll(/^name = "([^"]+)"$/gmu)]
  .map((match) => match[1])
  .filter((name) => name !== "openid4vci-fuzz")
  .sort();

if (fuzzTargets.length === 0) {
  fail("fuzz/Cargo.toml declares no fuzz targets");
}
for (const target of fuzzTargets) {
  if (!fuzzSmoke.includes(`"${target}"`)) {
    fail(`scripts/run-fuzz-smoke.sh does not run fuzz target ${target}`);
  }
  if (!fuzzWorkflow.includes(`- ${target}`)) {
    fail(`.github/workflows/fuzz.yml does not schedule fuzz target ${target}`);
  }
}
assertWorkflowJobContains(
  fuzzCiWorkflow,
  "build",
  "scripts/run-fuzz-smoke.sh",
);
assertWorkflowJobContains(
  fuzzCiWorkflow,
  "scheduled",
  "scripts/run-fuzz-smoke.sh",
);
if (!fuzzSmoke.includes('cargo "+${FUZZ_TOOLCHAIN}" fuzz build')) {
  fail("scripts/run-fuzz-smoke.sh does not build all fuzz targets once");
}
if (fuzzSmoke.includes("cargo run")) {
  fail("scripts/run-fuzz-smoke.sh invokes Cargo once per fuzz target");
}
assertNotContains(
  rustCiWorkflow,
  "cargo check --locked --workspace --no-default-features --features native",
);

const ssiRemoteResolution = spawnSync(
  process.execPath,
  ["scripts/check-ssi-remote-resolution.mjs"],
  { cwd: root, encoding: "utf8" },
);
if (ssiRemoteResolution.status !== 0) {
  const detail = ssiRemoteResolution.stderr.trim();
  fail(
    `SSI remote dependency resolution failed${
      detail.length === 0 ? "" : `: ${detail}`
    }`,
  );
}

console.log(`release readiness checks passed for ${fuzzTargets.length} fuzz targets`);
