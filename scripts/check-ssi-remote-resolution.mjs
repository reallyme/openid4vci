#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const manifest = readFileSync(resolve(root, "Cargo.toml"), "utf8");
const requiredVersion = "0.3.3";
const cratesIoSource = "registry+https://github.com/rust-lang/crates.io-index";
const requiredDependencies = [
  { dependencyName: "reallyme-mdoc", packageName: "reallyme-mdoc" },
  {
    dependencyName: "reallyme-openid-oauth",
    packageName: "reallyme-openid-oauth",
  },
  {
    dependencyName: "reallyme-openid4vc-profiles",
    packageName: "reallyme-openid4vc-profiles",
  },
  { dependencyName: "reallyme-ssi-proto", packageName: "reallyme-ssi-proto" },
  {
    dependencyName: "reallyme-trust-core",
    packageName: "reallyme-trust-core",
  },
  { dependencyName: "envelopes-x509", packageName: "reallyme-trust-x509" },
  { dependencyName: "reallyme-revocation", packageName: "reallyme-revocation" },
];

function fail(message) {
  console.error(`SSI remote resolution check failed: ${message}`);
  process.exit(1);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

for (const { dependencyName, packageName } of requiredDependencies) {
  const dependencyPattern = new RegExp(
    `^${escapeRegExp(dependencyName)}\\s*=\\s*\\{([^}]+)\\}$`,
    "gmu",
  );
  const matches = [...manifest.matchAll(dependencyPattern)];
  if (matches.length !== 1 || matches[0][1] === undefined) {
    fail(`Cargo.toml must declare ${dependencyName} exactly once`);
  }

  const declaration = matches[0][1];
  const escapedVersion = requiredVersion.replaceAll(".", "\\.");
  if (
    !new RegExp(
      `version\\s*=\\s*"=${escapedVersion}"`,
      "u",
    ).test(declaration)
  ) {
    fail(`${dependencyName} must use exact version =${requiredVersion}`);
  }
  if (/\b(?:git|path)\s*=/u.test(declaration)) {
    fail(`${dependencyName} must resolve from crates.io`);
  }
  if (
    dependencyName !== packageName &&
    !new RegExp(
      `package\\s*=\\s*"${escapeRegExp(packageName)}"`,
      "u",
    ).test(declaration)
  ) {
    fail(`${dependencyName} must select package ${packageName}`);
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

function validateLockedPackage(lockfile, packages, packageName, source) {
  const matches = packages.filter(
    (cargoPackage) => cargoPackage.name === packageName,
  );
  if (matches.length !== 1) {
    fail(`${lockfile} must contain exactly one ${packageName} package`);
  }

  const [cargoPackage] = matches;
  if (
    cargoPackage.version !== requiredVersion ||
    cargoPackage.source !== source
  ) {
    fail(
      `${lockfile} must resolve ${packageName} ${requiredVersion} from ${source}`,
    );
  }
  if (source === cratesIoSource && cargoPackage.checksum === undefined) {
    fail(`${lockfile} must lock the crates.io checksum for ${packageName}`);
  }
}

const rootPackages = readLockedPackages("Cargo.lock");
for (const { packageName } of requiredDependencies) {
  validateLockedPackage(
    "Cargo.lock",
    rootPackages,
    packageName,
    cratesIoSource,
  );
}
for (const packageName of ["reallyme-credential-status"]) {
  validateLockedPackage("Cargo.lock", rootPackages, packageName, cratesIoSource);
}

const fuzzPackages = readLockedPackages("fuzz/Cargo.lock");
for (const packageName of [
  "reallyme-credential-status",
  "reallyme-openid-oauth",
  "reallyme-openid4vc-profiles",
  "reallyme-revocation",
  "reallyme-ssi-proto",
  "reallyme-trust-core",
  "reallyme-trust-x509",
]) {
  validateLockedPackage(
    "fuzz/Cargo.lock",
    fuzzPackages,
    packageName,
    cratesIoSource,
  );
}

console.log(
  `SSI remote resolution check passed for ${requiredDependencies.length} crates at ${requiredVersion}`,
);
