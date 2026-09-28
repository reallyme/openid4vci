#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const facade = readFileSync(resolve(root, "crates/openid4vci/src/lib.rs"), "utf8");
const sdk = readFileSync(resolve(root, "crates/openid4vci/src/sdk.rs"), "utf8");
const manifest = readFileSync(resolve(root, "crates/openid4vci/Cargo.toml"), "utf8");
const failures = [];

const aliases = [
  ...facade.matchAll(
    /pub use (?:openid4vci|reallyme_openid4vci)_[a-z_]+ as ([a-z_]+);/g,
  ),
].map((match) => match[1]);
if (facade.includes("pub mod policy;")) {
  aliases.push("policy");
}
if (facade.includes("pub mod sdk;")) {
  aliases.push("sdk");
}

const expected = [
  "attestation",
  "http",
  "issuer",
  "policy",
  "profiles",
  "sdk",
  "types",
  "wallet",
];

const observed = [...new Set(aliases)].sort();
if (JSON.stringify(observed) !== JSON.stringify(expected)) {
  failures.push(
    `root facade changed; expected ${expected.join(", ")}, observed ${observed.join(", ")}`,
  );
}

if (!facade.includes("#[cfg(feature = \"codec\")]\npub mod sdk;")) {
  failures.push("canonical sdk module must remain gated by the codec feature");
}

for (const removed of [
  "pub use openid4vci_proto as proto;",
  "pub use openid4vci_proto_codec as proto_codec;",
]) {
  if (facade.includes(removed)) {
    failures.push(`deprecated root facade alias returned: ${removed}`);
  }
}
if (/^proto\s*=\s*\[/mu.test(manifest)) {
  failures.push("deprecated root proto feature returned; generated contracts belong under sdk");
}

for (const required of [
  "pub use openid4vci_proto::generated as protobuf;",
  "execute_operation_v1",
  "execute_operation_json_v1",
  "OpenId4VciErrorReason",
  "IdentityStackError",
]) {
  if (!sdk.includes(required)) {
    failures.push(`crates/openid4vci/src/sdk.rs is missing canonical generated boundary ${required}`);
  }
}

for (const forbidden of [
  "openid4vci_attestation",
  "reallyme_openid4vci_wallet",
  "openid4vci_http",
  "openid4vci_issuer",
  "openid4vci_profiles",
  "openid4vci_types",
  "serde_json::Value",
]) {
  if (sdk.includes(forbidden)) {
    failures.push(`crates/openid4vci/src/sdk.rs exposes non-generated DTO boundary ${forbidden}`);
  }
}

if (failures.length !== 0) {
  console.error("SDK facade inventory checks failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(`SDK facade inventory checks passed for ${expected.length} root surfaces`);
