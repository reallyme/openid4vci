#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const cratesIoSource = "registry+https://github.com/rust-lang/crates.io-index";
const manifestDependencies = [
  { manifest: "Cargo.toml", name: "reallyme-jose", version: "0.4.6" },
  { manifest: "Cargo.toml", name: "reallyme-codec", version: "0.3.2" },
  { manifest: "Cargo.toml", name: "reallyme-crypto", version: "0.3.17" },
  { manifest: "Cargo.toml", name: "reallyme-credential", version: "0.6.1" },
  {
    manifest: "Cargo.toml",
    name: "reallyme-credential-status",
    version: "0.6.1",
  },
  { manifest: "Cargo.toml", name: "reallyme-ssi-proto", version: "0.6.1" },
  {
    manifest: "Cargo.toml",
    name: "reallyme-openid-oauth",
    version: "0.6.1",
  },
  {
    manifest: "Cargo.toml",
    name: "reallyme-openid4vc-profiles",
    version: "0.6.1",
  },
  {
    manifest: "Cargo.toml",
    name: "reallyme-trust-core",
    version: "0.6.1",
  },
  {
    manifest: "Cargo.toml",
    name: "envelopes-x509",
    packageName: "reallyme-trust-x509",
    version: "0.6.1",
  },
  { manifest: "Cargo.toml", name: "reallyme-mdoc", version: "0.6.1" },
  {
    manifest: "Cargo.toml",
    name: "reallyme-revocation",
    version: "0.6.1",
  },
  { manifest: "Cargo.toml", name: "reallyme-cose", version: "0.2.10" },
  { manifest: "Cargo.toml", name: "reallyme-zk-api", version: "0.3.0" },
  {
    manifest: "crates/http/Cargo.toml",
    name: "reallyme-sd-jwt",
    version: "0.6.1",
  },
  {
    manifest: "fuzz/Cargo.toml",
    name: "reallyme-crypto",
    version: "0.3.17",
  },
];
const rootLockedDependencies = [
  { name: "reallyme-jose", version: "0.4.6" },
  { name: "reallyme-codec", version: "0.3.2" },
  { name: "reallyme-crypto", version: "0.3.17" },
  { name: "reallyme-credential", version: "0.6.1" },
  { name: "reallyme-credential-audit", version: "0.6.1" },
  { name: "reallyme-credential-claims", version: "0.6.1" },
  { name: "reallyme-credential-status", version: "0.6.1" },
  { name: "reallyme-ssi-proto", version: "0.6.1" },
  { name: "reallyme-openid-oauth", version: "0.6.1" },
  { name: "reallyme-openid4vc-profiles", version: "0.6.1" },
  { name: "reallyme-trust-core", version: "0.6.1" },
  { name: "reallyme-trust-x509", version: "0.6.1" },
  { name: "reallyme-mdoc", version: "0.6.1" },
  { name: "reallyme-revocation", version: "0.6.1" },
  { name: "reallyme-cose", version: "0.2.10" },
  { name: "reallyme-sd-jwt", version: "0.6.1" },
  { name: "reallyme-zk-api", version: "0.3.0" },
];
const fuzzLockedDependencies = rootLockedDependencies.filter(
  ({ name }) => name !== "reallyme-mdoc" && name !== "reallyme-sd-jwt",
);

function fail(message) {
  console.error(`published dependency resolution check failed: ${message}`);
  process.exit(1);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

for (const { manifest, name, packageName = name, version } of manifestDependencies) {
  const manifestContents = readFileSync(resolve(root, manifest), "utf8");
  const dependencyPattern = new RegExp(
    `^${escapeRegExp(name)}\\s*=\\s*\\{([^}]+)\\}$`,
    "gmu",
  );
  const matches = [...manifestContents.matchAll(dependencyPattern)];
  if (matches.length !== 1 || matches[0][1] === undefined) {
    fail(`${manifest} must declare ${name} exactly once`);
  }

  const declaration = matches[0][1];
  const exactVersion = new RegExp(
    `version\\s*=\\s*"=${escapeRegExp(version)}"`,
    "u",
  );
  if (!exactVersion.test(declaration)) {
    fail(`${manifest} ${name} must use exact version =${version}`);
  }
  if (/\b(?:git|path|registry)\s*=/u.test(declaration)) {
    fail(`${manifest} ${name} must resolve from crates.io`);
  }
  if (
    packageName !== name &&
    !new RegExp(
      `package\\s*=\\s*"${escapeRegExp(packageName)}"`,
      "u",
    ).test(declaration)
  ) {
    fail(`${manifest} ${name} must select package ${packageName}`);
  }
}

function readLockedPackages(lockfile) {
  return readFileSync(resolve(root, lockfile), "utf8")
    .split("[[package]]")
    .slice(1)
    .map((block) => ({
      name: block.match(/^name = "([^"]+)"$/mu)?.[1],
      version: block.match(/^version = "([^"]+)"$/mu)?.[1],
      source: block.match(/^source = "([^"]+)"$/mu)?.[1],
      checksum: block.match(/^checksum = "([0-9a-f]{64})"$/mu)?.[1],
    }));
}

function validateLockedPackage(lockfile, packages, expected) {
  const matches = packages.filter(({ name }) => name === expected.name);
  if (matches.length !== 1) {
    fail(`${lockfile} must contain exactly one ${expected.name} package`);
  }

  const [cargoPackage] = matches;
  if (
    cargoPackage.version !== expected.version ||
    cargoPackage.source !== cratesIoSource
  ) {
    fail(
      `${lockfile} must resolve ${expected.name} ${expected.version} from crates.io`,
    );
  }
  if (cargoPackage.checksum === undefined) {
    fail(`${lockfile} must lock the crates.io checksum for ${expected.name}`);
  }
}

const rootPackages = readLockedPackages("Cargo.lock");
for (const expected of rootLockedDependencies) {
  validateLockedPackage("Cargo.lock", rootPackages, expected);
}

const fuzzPackages = readLockedPackages("fuzz/Cargo.lock");
for (const expected of fuzzLockedDependencies) {
  validateLockedPackage("fuzz/Cargo.lock", fuzzPackages, expected);
}

console.log(
  `dependency resolution check passed for ${rootLockedDependencies.length} registry crates`,
);
