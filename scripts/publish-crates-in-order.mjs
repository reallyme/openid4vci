// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const MODE_INSPECT = "inspect";
const MODE_ORDER = "order";
const MODE_PUBLISH = "publish";
const MAX_PUBLISH_ATTEMPTS = 12;
const CRATES_IO_DEFAULT_RATE_LIMIT_RETRY_MS = 60000;
const CRATES_IO_INDEX_RETRY_BASE_MS = 15000;
const CRATES_IO_ARCHIVE_VERIFY_RETRIES = "12";
const CRATES_IO_ARCHIVE_VERIFY_RETRY_DELAY_SECONDS = "10";
const CRATES_IO_ARCHIVE_VERIFY_MAX_SECONDS = "180";
const APPROVED_PUBLIC_PACKAGES = new Set([
  "reallyme-openid4vci-proto",
  "reallyme-openid4vci-types",
  "reallyme-openid4vci-wallet",
]);
const REQUIRED_PUBLISH_ORDER_EDGES = [
  ["reallyme-openid4vci-types", "reallyme-openid4vci-wallet"],
];
const args = process.argv.slice(2);
const mode = args[0] ?? MODE_INSPECT;
const allowDirty = args.includes("--allow-dirty");
const unknownArgs = args.slice(1).filter((arg) => arg !== "--allow-dirty");
const releaseVersion = process.env.RELEASE_VERSION ?? "";
const releaseSha = process.env.RELEASE_SHA ?? "";
const publicationLedgerPath = process.env.PUBLICATION_LEDGER_PATH ?? "";

if (
  (mode !== MODE_INSPECT && mode !== MODE_ORDER && mode !== MODE_PUBLISH) ||
  unknownArgs.length !== 0
) {
  console.error(
    `usage: node scripts/publish_crates_in_order.mjs ${MODE_INSPECT}|${MODE_ORDER}|${MODE_PUBLISH} [--allow-dirty]`,
  );
  process.exit(2);
}

if (allowDirty && mode !== MODE_INSPECT && mode !== MODE_ORDER) {
  console.error("--allow-dirty is only supported for local package inspection and order checks");
  process.exit(2);
}

if (mode === MODE_PUBLISH && releaseVersion.length === 0) {
  console.error("RELEASE_VERSION must be set when publishing crates.");
  process.exit(2);
}

if (
  mode === MODE_PUBLISH &&
  publicationLedgerPath.length !== 0 &&
  !/^[0-9a-f]{40}$/u.test(releaseSha)
) {
  console.error("RELEASE_SHA must be an exact Git commit when recording publication state.");
  process.exit(2);
}

if (releaseVersion.length !== 0 && !/^[0-9]+[.][0-9]+[.][0-9]+$/u.test(releaseVersion)) {
  console.error("RELEASE_VERSION must be an exact semver release such as 0.1.0.");
  process.exit(2);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

function sleepMs(delayMs) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
}

function retryAfterMs(output) {
  const match = /try again after ([^\n.]+ GMT)/i.exec(output);
  if (!match) {
    return null;
  }

  const retryAt = Date.parse(match[1]);
  if (!Number.isFinite(retryAt)) {
    return null;
  }

  const delayMs = retryAt - Date.now() + 10000;
  return Math.max(delayMs, 10000);
}

const metadataResult = run(
  "cargo",
  ["metadata", "--locked", "--format-version", "1", "--no-deps"],
  {
    capture: true,
  },
);

if (metadataResult.status !== 0) {
  process.stderr.write(metadataResult.stderr);
  process.exit(metadataResult.status ?? 1);
}

const metadata = JSON.parse(metadataResult.stdout);
const packageDirectory = path.join(metadata.target_directory, "package");

function isPublishablePackage(pkg) {
  return !(Array.isArray(pkg.publish) && pkg.publish.length === 0);
}

const publishable = new Map();
for (const pkg of metadata.packages) {
  if (isPublishablePackage(pkg)) {
    publishable.set(pkg.name, pkg);
  }
}

const unexpectedPublicPackages = [...publishable.keys()].filter(
  (name) => !APPROVED_PUBLIC_PACKAGES.has(name),
);
const missingPublicPackages = [...APPROVED_PUBLIC_PACKAGES].filter(
  (name) => !publishable.has(name),
);
if (unexpectedPublicPackages.length !== 0 || missingPublicPackages.length !== 0) {
  console.error("publishable package set differs from the approved release policy");
  for (const name of unexpectedPublicPackages.sort()) {
    console.error(`- unexpected public package: ${name}`);
  }
  for (const name of missingPublicPackages.sort()) {
    console.error(`- missing public package: ${name}`);
  }
  process.exit(1);
}

function dependencyPackageName(dep) {
  return dep.package ?? dep.name;
}

function isWorkspacePathDependency(dep) {
  return (
    dep.source === null &&
    typeof dep.path === "string" &&
    publishable.has(dependencyPackageName(dep))
  );
}

function isPublishOrderingDependency(dep) {
  // crates.io resolves normalized dev-dependencies while validating an upload,
  // so public path-based test dependencies must be available first as well.
  return isWorkspacePathDependency(dep);
}

function parseVersion(version) {
  const parts = version.split(".");
  if (!/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(version)) {
    return null;
  }

  const parsed = parts.map((part) => Number.parseInt(part, 10));
  if (parsed.some((part) => !Number.isSafeInteger(part) || part < 0)) {
    return null;
  }

  return {
    major: parsed[0],
    minor: parsed[1],
    patch: parsed[2],
  };
}

function isCaretReqSatisfied(req, version) {
  if (!req.startsWith("^")) {
    return req === `=${version}` || req === version;
  }

  const minimum = parseVersion(req.slice(1));
  const actual = parseVersion(version);
  if (minimum === null || actual === null) {
    return false;
  }

  if (actual.major !== minimum.major) {
    return false;
  }

  if (minimum.major === 0 && actual.minor !== minimum.minor) {
    return false;
  }

  // Cargo keeps ^0.0.x within that exact patch release.
  if (minimum.major === 0 && minimum.minor === 0 && actual.patch !== minimum.patch) {
    return false;
  }

  if (actual.minor < minimum.minor) {
    return false;
  }

  if (actual.minor === minimum.minor && actual.patch < minimum.patch) {
    return false;
  }

  return true;
}

function checkPathDependencyVersions() {
  const failures = [];
  for (const pkg of publishable.values()) {
    for (const dep of pkg.dependencies) {
      if (!isPublishOrderingDependency(dep)) {
        continue;
      }

      const target = publishable.get(dependencyPackageName(dep));
      if (!isCaretReqSatisfied(dep.req, target.version)) {
        failures.push(
          `${pkg.name} depends on ${dep.name} with ${dep.req}; local version is ${target.version}`,
        );
      }
    }
  }

  if (failures.length !== 0) {
    console.error("publishable workspace path dependency versions are stale:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

function checkReleaseVersion() {
  if (releaseVersion.length === 0) {
    return;
  }

  const failures = [];
  for (const pkg of publishable.values()) {
    if (pkg.version !== releaseVersion) {
      failures.push(`${pkg.name} is ${pkg.version}; expected ${releaseVersion}`);
    }
  }
  if (failures.length !== 0) {
    console.error("publishable crate versions do not match RELEASE_VERSION:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

const visiting = new Set();
const visited = new Set();
const ordered = [];

function visit(pkg) {
  if (visited.has(pkg.name)) {
    return;
  }
  if (visiting.has(pkg.name)) {
    console.error(`workspace publish dependency cycle at ${pkg.name}`);
    process.exit(1);
  }

  visiting.add(pkg.name);
  for (const dep of pkg.dependencies) {
    const depName = dependencyPackageName(dep);
    if (isPublishOrderingDependency(dep) && publishable.has(depName)) {
      visit(publishable.get(depName));
    }
  }
  visiting.delete(pkg.name);
  visited.add(pkg.name);
  ordered.push(pkg);
}

for (const pkg of publishable.values()) {
  visit(pkg);
}

console.log(`Publish order (${ordered.length} crates):`);
for (const pkg of ordered) {
  console.log(`- ${pkg.name} ${pkg.version}`);
}

function checkRequiredPublishOrderEdges() {
  const failures = [];
  const orderedPackageNames = new Set(orderedIndexByName.keys());

  for (const [dependencyName, packageName] of REQUIRED_PUBLISH_ORDER_EDGES) {
    const dependencyIndex = orderedIndexByName.get(dependencyName);
    const packageIndex = orderedIndexByName.get(packageName);
    if (dependencyIndex === undefined || packageIndex === undefined) {
      failures.push(`${dependencyName} before ${packageName} cannot be checked; package is missing`);
      continue;
    }

    if (dependencyIndex >= packageIndex) {
      failures.push(`${dependencyName} must publish before ${packageName}`);
    }
  }

  if (failures.length !== 0) {
    console.error(
      `publishable packages discovered: ${[...orderedPackageNames].sort().join(", ")}`,
    );
    console.error("required publish dependency order is not satisfied:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

const orderedIndexByName = new Map();
ordered.forEach((pkg, index) => {
  orderedIndexByName.set(pkg.name, index);
});

checkPathDependencyVersions();
checkRequiredPublishOrderEdges();
checkReleaseVersion();

if (mode === MODE_ORDER) {
  process.exit(0);
}

const unpackDirectory = path.join(packageDirectory, "release-preflight");
const checkTargetDirectory = path.join(
  packageDirectory,
  "release-preflight-target",
);

if (mode === MODE_INSPECT) {
  // Package the reviewed release set as one workspace operation so Cargo can
  // normalize dependencies whose earlier versions are not in the registry yet.
  const packageArgs = ["package", "--workspace", "--no-verify", "--locked"];
  for (const pkg of metadata.packages) {
    if (!publishable.has(pkg.name)) {
      packageArgs.push("--exclude", pkg.name);
    }
  }
  if (allowDirty) {
    packageArgs.push("--allow-dirty");
  }
  const packageResult = run("cargo", packageArgs);
  if (packageResult.status !== 0) {
    process.exit(packageResult.status ?? 1);
  }

  fs.rmSync(unpackDirectory, { force: true, recursive: true });
  fs.mkdirSync(unpackDirectory, { recursive: true });
  for (const pkg of ordered) {
    const archive = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
    const extractResult = run("tar", ["-xzf", archive, "-C", unpackDirectory]);
    if (extractResult.status !== 0) {
      process.exit(extractResult.status ?? 1);
    }
  }
}

function unresolvedRegistryPackages(output) {
  const missing = [];
  const noMatchPattern = /no matching package named `([^`]+)` found/g;
  for (let match = noMatchPattern.exec(output); match !== null; match = noMatchPattern.exec(output)) {
    missing.push(match[1]);
  }

  const versionSelectPattern = /failed to select a version for the requirement `([^`\s]+) =/g;
  for (
    let match = versionSelectPattern.exec(output);
    match !== null;
    match = versionSelectPattern.exec(output)
  ) {
    missing.push(match[1]);
  }

  return [...new Set(missing)];
}

function isEarlierWorkspaceDependency(pkg, depName) {
  const pkgIndex = orderedIndexByName.get(pkg.name);
  const depIndex = orderedIndexByName.get(depName);
  return depIndex !== undefined && pkgIndex !== undefined && depIndex < pkgIndex;
}

function workspaceDependencyClosure(pkg) {
  const closure = new Set();

  function visitDependencies(current) {
    for (const dependency of current.dependencies) {
      if (!isPublishOrderingDependency(dependency)) {
        continue;
      }
      const dependencyName = dependencyPackageName(dependency);
      if (closure.has(dependencyName)) {
        continue;
      }
      closure.add(dependencyName);
      const dependencyPackage = publishable.get(dependencyName);
      if (dependencyPackage !== undefined) {
        visitDependencies(dependencyPackage);
      }
    }
  }

  visitDependencies(pkg);
  return closure;
}

function inspectPackage(pkg) {
  const listArgs = ["package", "-p", pkg.name, "--list", "--locked"];
  if (allowDirty) {
    listArgs.push("--allow-dirty");
  }
  const listResult = run("cargo", listArgs);
  if (listResult.status !== 0) {
    process.exit(listResult.status ?? 1);
  }

  const manifestPath = path.join(unpackDirectory, `${pkg.name}-${pkg.version}`, "Cargo.toml");
  const patchArgs = [];
  const workspaceDependencies = workspaceDependencyClosure(pkg);
  for (const dependency of ordered) {
    if (!workspaceDependencies.has(dependency.name)) {
      continue;
    }
    const dependencyPath = path.join(unpackDirectory, `${dependency.name}-${dependency.version}`);
    patchArgs.push(
      "--config",
      `patch.crates-io.'${dependency.name}'.path=${JSON.stringify(dependencyPath)}`,
    );
  }

  if (patchArgs.length !== 0) {
    // A normalized archive records not-yet-published workspace dependencies as
    // registry packages. Applying the reviewed local archives necessarily
    // changes those source entries. Refresh only those entries in this
    // disposable lockfile while network access is available; a fresh hosted
    // runner cannot be assumed to have every locked third-party crate cached.
    const directWorkspaceDependencies = pkg.dependencies
      .filter(isPublishOrderingDependency)
      .map(dependencyPackageName);
    for (const dependencyName of directWorkspaceDependencies) {
      const updateArgs = [
        "update",
        "--manifest-path",
        manifestPath,
        "-p",
        dependencyName,
        ...patchArgs,
      ];
      const updateResult = run("cargo", updateArgs);
      if (updateResult.status !== 0) {
        process.exit(updateResult.status ?? 1);
      }
    }
  }

  // Materialize the complete, locked dependency graph before enforcing an
  // offline build. Supplying the same patch configuration ensures unpublished
  // workspace dependencies resolve only to the normalized archives reviewed
  // earlier in this run.
  const fetchArgs = [
    "fetch",
    "--locked",
    "--manifest-path",
    manifestPath,
    ...patchArgs,
  ];
  const fetchResult = run("cargo", fetchArgs);
  if (fetchResult.status !== 0) {
    process.exit(fetchResult.status ?? 1);
  }

  const checkArgs = [
    "check",
    "--manifest-path",
    manifestPath,
    "--all-features",
    "--locked",
    "--offline",
    "--target-dir",
    // A registry package and the reviewed path package may have the same name
    // and version but expose different source bytes. Isolate each normalized
    // archive's build cache so Cargo cannot reuse stale metadata from an
    // earlier package inspection and mask (or manufacture) API mismatches.
    path.join(checkTargetDirectory, pkg.name),
    ...patchArgs,
  ];
  const checkResult = run("cargo", checkArgs);
  if (checkResult.status !== 0) {
    process.exit(checkResult.status ?? 1);
  }

  // The normalized archive was checked explicitly above, with unpublished
  // workspace dependencies patched to the reviewed archives. Re-running
  // Cargo's verification build here would compile the same archive twice.
  const dryRunArgs = [
    "publish",
    "-p",
    pkg.name,
    "--dry-run",
    "--no-verify",
    "--locked",
  ];
  if (allowDirty) {
    dryRunArgs.push("--allow-dirty");
  }
  const dryRunResult = run("cargo", dryRunArgs, { capture: true });
  process.stdout.write(dryRunResult.stdout);
  process.stderr.write(dryRunResult.stderr);
  if (dryRunResult.status === 0) {
    return;
  }

  const combined = `${dryRunResult.stdout}\n${dryRunResult.stderr}`;
  const missing = unresolvedRegistryPackages(combined);
  if (
    missing.length !== 0 &&
    missing.every((depName) => isEarlierWorkspaceDependency(pkg, depName))
  ) {
    console.log(
      `${pkg.name} dry-run reached unpublished ordered workspace dependencies: ${missing.join(", ")}`,
    );
    return;
  }

  process.exit(dryRunResult.status ?? 1);
}

function publishPackage(pkg) {
  const packageResult = run("cargo", [
    "package",
    "-p",
    pkg.name,
    "--no-verify",
    "--locked",
  ]);
  if (packageResult.status !== 0) {
    process.exit(packageResult.status ?? 1);
  }

  const reviewedDirectory = process.env.REVIEWED_CRATE_DIRECTORY;
  if (typeof reviewedDirectory !== "string" || reviewedDirectory.length === 0) {
    console.error("REVIEWED_CRATE_DIRECTORY must identify the preflight crate archives");
    process.exit(2);
  }
  const archiveName = `${pkg.name}-${pkg.version}.crate`;
  const localArchive = path.join(packageDirectory, archiveName);
  const reviewedArchive = path.resolve(reviewedDirectory, archiveName);
  if (!fs.existsSync(reviewedArchive)) {
    console.error(`${pkg.name} reviewed package archive is missing`);
    process.exit(1);
  }
  const localDigest = createHash("sha256").update(fs.readFileSync(localArchive)).digest("hex");
  const reviewedDigest = createHash("sha256")
    .update(fs.readFileSync(reviewedArchive))
    .digest("hex");
  if (localDigest !== reviewedDigest) {
    console.error(`${pkg.name} package archive differs from reviewed preflight bytes`);
    process.exit(1);
  }

  // Verification happens in the credential-free preflight. The crates.io
  // release token is scoped only to upload so dependency build scripts never
  // receive it.
  const args = ["publish", "-p", pkg.name, "--locked", "--no-verify"];

  for (let attempt = 1; attempt <= MAX_PUBLISH_ATTEMPTS; attempt += 1) {
    const result = run("cargo", args, { capture: true });
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);

    if (result.status === 0) {
      verifyPublishedPackageMatches(pkg);
      return "published";
    }

    const combined = `${result.stdout}\n${result.stderr}`;
    if (combined.includes("already uploaded") || combined.includes("already exists")) {
      verifyPublishedPackageMatches(pkg);
      console.log(`${pkg.name} ${pkg.version} is already published; continuing.`);
      return "verified_existing";
    }

    const lowerCombined = combined.toLowerCase();
    const rateLimitDelayMs = retryAfterMs(combined);
    if (
      lowerCombined.includes("too many requests") ||
      lowerCombined.includes("rate-limited") ||
      lowerCombined.includes("rate limited") ||
      lowerCombined.includes("rate limit") ||
      /\b429\b/u.test(lowerCombined)
    ) {
      // Exhaustion must fail the release before attempting dependent crates.
      if (attempt === MAX_PUBLISH_ATTEMPTS) {
        console.error(`publication retry limit reached for ${pkg.name}`);
        process.exit(result.status ?? 1);
      }
      const delayMs = rateLimitDelayMs ?? CRATES_IO_DEFAULT_RATE_LIMIT_RETRY_MS;
      console.log(
        `crates.io rate-limited new crate uploads; retrying ${pkg.name} in ${Math.ceil(delayMs / 1000)}s...`,
      );
      sleepMs(delayMs);
      continue;
    }

    const registryIndexIsStale =
      combined.includes("no matching package named") ||
      combined.includes("failed to select a version for the requirement");
    if (!registryIndexIsStale || attempt === MAX_PUBLISH_ATTEMPTS) {
      process.exit(result.status ?? 1);
    }

    const delayMs = attempt * CRATES_IO_INDEX_RETRY_BASE_MS;
    console.log(
      `crates.io index has not observed a freshly published dependency yet; retrying ${pkg.name} in ${delayMs / 1000}s...`,
    );
    sleepMs(delayMs);
  }
}

const publicationLedger = {
  schema: "reallyme.openid4vci.crates-publication-ledger.v1",
  repository: "reallyme/openid4vci",
  source_commit: releaseSha,
  release_version: releaseVersion,
  state: "not_started",
  crates: ordered.map((pkg, publishOrder) => ({
    name: pkg.name,
    version: pkg.version,
    publish_order: publishOrder,
    state: "pending",
    archive_sha256: null,
  })),
};

function writePublicationLedger() {
  if (mode !== MODE_PUBLISH || publicationLedgerPath.length === 0) {
    return;
  }
  fs.mkdirSync(path.dirname(publicationLedgerPath), { recursive: true });
  const temporaryPath = `${publicationLedgerPath}.tmp`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify(publicationLedger, null, 2)}\n`, {
    mode: 0o600,
  });
  fs.renameSync(temporaryPath, publicationLedgerPath);
}

function packagedArchiveSha256(pkg) {
  const archive = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
  if (!fs.existsSync(archive)) {
    return null;
  }
  return createHash("sha256").update(fs.readFileSync(archive)).digest("hex");
}

function verifyPublishedPackageMatches(pkg) {
  const localArchive = path.join(packageDirectory, `${pkg.name}-${pkg.version}.crate`);
  if (!fs.existsSync(localArchive)) {
    console.error(`${pkg.name} ${pkg.version} local package archive is missing`);
    process.exit(1);
  }

  const comparisonDirectory = fs.mkdtempSync(path.join(packageDirectory, "published-"));
  const publishedArchive = path.join(comparisonDirectory, `${pkg.name}-${pkg.version}.crate`);
  const packageName = encodeURIComponent(pkg.name);
  const packageVersion = encodeURIComponent(pkg.version);
  const downloadUrl =
    `https://static.crates.io/crates/${packageName}/${packageName}-${packageVersion}.crate`;

  try {
    const downloadResult = run(
      "curl",
      [
        "--fail-with-body",
        "--location",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--retry",
        CRATES_IO_ARCHIVE_VERIFY_RETRIES,
        "--retry-delay",
        CRATES_IO_ARCHIVE_VERIFY_RETRY_DELAY_SECONDS,
        "--retry-max-time",
        CRATES_IO_ARCHIVE_VERIFY_MAX_SECONDS,
        "--retry-all-errors",
        "--output",
        publishedArchive,
        downloadUrl,
      ],
      { capture: true },
    );
    if (downloadResult.status !== 0) {
      process.stdout.write(downloadResult.stdout);
      process.stderr.write(downloadResult.stderr);
      process.exit(downloadResult.status ?? 1);
    }

    const localChecksum = createHash("sha256").update(fs.readFileSync(localArchive)).digest("hex");
    const publishedChecksum = createHash("sha256")
      .update(fs.readFileSync(publishedArchive))
      .digest("hex");
    if (localChecksum !== publishedChecksum) {
      console.error(
        `${pkg.name} ${pkg.version} is already published from different source bytes`,
      );
      process.exit(1);
    }
  } finally {
    fs.rmSync(comparisonDirectory, { force: true, recursive: true });
  }
}

if (mode === MODE_PUBLISH) {
  publicationLedger.state = "in_progress";
  writePublicationLedger();
}

for (const pkg of ordered) {
  if (mode === MODE_INSPECT) {
    inspectPackage(pkg);
    continue;
  }

  const ledgerEntry = publicationLedger.crates.find((entry) => entry.name === pkg.name);
  if (ledgerEntry !== undefined) {
    ledgerEntry.state = "attempting";
    writePublicationLedger();
  }
  const publishState = publishPackage(pkg);
  if (ledgerEntry !== undefined) {
    ledgerEntry.state = publishState;
    ledgerEntry.archive_sha256 = packagedArchiveSha256(pkg);
    writePublicationLedger();
  }
}

if (mode === MODE_PUBLISH) {
  publicationLedger.state = "completed";
  writePublicationLedger();
}
