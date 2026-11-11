// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Produces redacted parser-comparison evidence from pinned EUDI resources.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use openid4vci_profiles::parse_credential_reuse_policy;
use openid4vci_types::{
    CredentialErrorResponse, CredentialOffer, CredentialResponse, IssuerMetadata, NonceResponse,
    ProblemDetails,
};
use reallyme_crypto::sha2::digest as digest_sha2_256;
use serde::{Deserialize, Serialize};

const EXIT_INVALID_ARGS: u8 = 2;
const EXIT_IO: u8 = 3;
const EXIT_JSON: u8 = 4;
const EXIT_PATH: u8 = 5;
const EXIT_INTEGRITY: u8 = 6;
const EXPECTATIONS_JSON: &str =
    include_str!("../../../conformance/eudi/eudi-jvm-v0.16.0-resource-expectations.json");

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => ExitCode::from(reason.exit_code()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolFailure {
    InvalidArgs,
    Io,
    Json,
    Path,
    Integrity,
}

impl ToolFailure {
    const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidArgs => EXIT_INVALID_ARGS,
            Self::Io => EXIT_IO,
            Self::Json => EXIT_JSON,
            Self::Path => EXIT_PATH,
            Self::Integrity => EXIT_INTEGRITY,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ParserTarget {
    IssuerMetadata,
    CredentialOffer,
    NonceResponse,
    CredentialResponse,
    CredentialErrorResponse,
    ProblemDetails,
}

impl ParserTarget {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::IssuerMetadata => "types::IssuerMetadata",
            Self::CredentialOffer => "types::CredentialOffer",
            Self::NonceResponse => "types::NonceResponse",
            Self::CredentialResponse => "types::CredentialResponse",
            Self::CredentialErrorResponse => "types::CredentialErrorResponse",
            Self::ProblemDetails => "types::ProblemDetails",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ParserOutcome {
    Accepted,
    Rejected,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Expectation {
    Accept,
    Reject,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SemanticProfile {
    EtsiReusePolicy,
}

impl SemanticProfile {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::EtsiReusePolicy => "profiles::etsi_reuse_policy",
        }
    }
}

#[derive(Debug, Serialize)]
struct Summary {
    schema_version: u8,
    source_id: String,
    source_release: String,
    source_commit: String,
    resource_root: String,
    generated_by: &'static str,
    result: &'static str,
    totals: Totals,
}

#[derive(Debug, Default, Serialize)]
struct Totals {
    resources_seen: usize,
    compared: usize,
    accepted: usize,
    rejected: usize,
    skipped: usize,
    expectation_matches: usize,
    expectation_mismatches: usize,
}

#[derive(Debug, Serialize)]
struct FixtureManifest {
    schema_version: u8,
    source_id: String,
    source_release: String,
    source_commit: String,
    resource_root: String,
    resources: Vec<FixtureResource>,
}

#[derive(Debug, Serialize)]
struct FixtureResource {
    relative_path: String,
    sha256: String,
    parser_target: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_profile: Option<&'static str>,
    expectation: Expectation,
}

#[derive(Debug, Serialize)]
struct ParserComparison {
    schema_version: u8,
    source_id: String,
    source_release: String,
    source_commit: String,
    comparisons: Vec<ComparisonRecord>,
}

#[derive(Debug, Serialize)]
struct ComparisonRecord {
    relative_path: String,
    sha256: String,
    parser_target: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_profile: Option<&'static str>,
    expectation: Expectation,
    outcome: ParserOutcome,
    expectation_matched: bool,
}

#[derive(Debug, Deserialize)]
struct ExpectedFixtureManifest {
    schema_version: u8,
    source_id: String,
    source_release: String,
    source_commit: String,
    resources: Vec<ExpectedFixture>,
}

#[derive(Debug, Deserialize)]
struct ExpectedFixture {
    relative_path: String,
    sha256: String,
    parser_target: Option<ParserTarget>,
    semantic_profile: Option<SemanticProfile>,
    expectation: Expectation,
}

struct Config {
    source_id: String,
    source_release: String,
    source_commit: String,
    resource_root: PathBuf,
    evidence_dir: PathBuf,
}

fn run() -> Result<(), ToolFailure> {
    let config = read_config()?;
    let expected = read_expectations(&config)?;
    fs::create_dir_all(&config.evidence_dir).map_err(|_| ToolFailure::Io)?;

    let mut files = Vec::new();
    collect_json_files(&config.resource_root, &mut files)?;
    let mut actual_files = files
        .into_iter()
        .map(|file| {
            let relative = relative_path_string(&config.resource_root, &file)?;
            Ok((relative, file))
        })
        .collect::<Result<BTreeMap<_, _>, ToolFailure>>()?;
    if actual_files.len() != expected.resources.len() {
        return Err(ToolFailure::Integrity);
    }

    let mut totals = Totals::default();
    let mut resources = Vec::with_capacity(expected.resources.len());
    let mut comparisons = Vec::with_capacity(expected.resources.len());

    for fixture in expected.resources {
        totals.resources_seen = increment(totals.resources_seen)?;
        validate_relative_path(&fixture.relative_path)?;
        let file = actual_files
            .remove(&fixture.relative_path)
            .ok_or(ToolFailure::Integrity)?;
        let body = fs::read_to_string(&file).map_err(|_| ToolFailure::Io)?;
        let sha256 = sha256_hex(body.as_bytes());
        if sha256 != fixture.sha256 {
            return Err(ToolFailure::Integrity);
        }
        let outcome = fixture
            .parser_target
            .map_or(ParserOutcome::Skipped, |target| {
                parse(target, fixture.semantic_profile, &body)
            });
        update_totals(&mut totals, fixture.expectation, outcome)?;

        resources.push(FixtureResource {
            relative_path: fixture.relative_path.clone(),
            sha256: sha256.clone(),
            parser_target: fixture.parser_target.map(ParserTarget::wire_name),
            semantic_profile: fixture.semantic_profile.map(SemanticProfile::wire_name),
            expectation: fixture.expectation,
        });
        comparisons.push(ComparisonRecord {
            relative_path: fixture.relative_path,
            sha256,
            parser_target: fixture.parser_target.map(ParserTarget::wire_name),
            semantic_profile: fixture.semantic_profile.map(SemanticProfile::wire_name),
            expectation: fixture.expectation,
            outcome,
            expectation_matched: expectation_matches(fixture.expectation, outcome),
        });
    }
    if !actual_files.is_empty() {
        return Err(ToolFailure::Integrity);
    }

    let result = if totals.expectation_mismatches == 0 {
        "passed"
    } else {
        "failed"
    };
    let resource_root = redacted_resource_root(&config.source_id);
    let summary = Summary {
        schema_version: 1,
        source_id: config.source_id.clone(),
        source_release: config.source_release.clone(),
        source_commit: config.source_commit.clone(),
        resource_root: resource_root.clone(),
        generated_by: "openid4vci-conformance compare_eudi_reference_resources",
        result,
        totals,
    };
    let fixture_manifest = FixtureManifest {
        schema_version: 1,
        source_id: config.source_id.clone(),
        source_release: config.source_release.clone(),
        source_commit: config.source_commit.clone(),
        resource_root,
        resources,
    };
    let parser_comparison = ParserComparison {
        schema_version: 1,
        source_id: config.source_id,
        source_release: config.source_release,
        source_commit: config.source_commit,
        comparisons,
    };

    write_json(&config.evidence_dir.join("summary.json"), &summary)?;
    write_json(
        &config.evidence_dir.join("fixture_manifest.json"),
        &fixture_manifest,
    )?;
    write_json(
        &config.evidence_dir.join("parser_comparison.json"),
        &parser_comparison,
    )?;
    Ok(())
}

fn read_expectations(config: &Config) -> Result<ExpectedFixtureManifest, ToolFailure> {
    let manifest: ExpectedFixtureManifest =
        serde_json::from_str(EXPECTATIONS_JSON).map_err(|_| ToolFailure::Json)?;
    if manifest.schema_version != 1
        || manifest.source_id != config.source_id
        || manifest.source_release != config.source_release
        || manifest.source_commit != config.source_commit
    {
        return Err(ToolFailure::Integrity);
    }
    Ok(manifest)
}

fn redacted_resource_root(source_id: &str) -> String {
    match source_id {
        "eudi-jvm-openid4vci" => "upstream:eudi-jvm-openid4vci/src/test/resources".to_owned(),
        "eudi-ios-openid4vci" => "upstream:eudi-ios-openid4vci/Sources/Resources".to_owned(),
        _ => ["upstream:", source_id, "/resources"].concat(),
    }
}

fn read_config() -> Result<Config, ToolFailure> {
    let args: Vec<OsString> = env::args_os().collect();
    if args.len() != 6 {
        return Err(ToolFailure::InvalidArgs);
    }
    Ok(Config {
        source_id: os_arg_to_string(&args[1])?,
        source_release: os_arg_to_string(&args[2])?,
        source_commit: os_arg_to_string(&args[3])?,
        resource_root: PathBuf::from(&args[4]),
        evidence_dir: PathBuf::from(&args[5]),
    })
}

fn os_arg_to_string(value: &OsString) -> Result<String, ToolFailure> {
    value
        .clone()
        .into_string()
        .map_err(|_| ToolFailure::InvalidArgs)
}

fn collect_json_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), ToolFailure> {
    let entries = fs::read_dir(root).map_err(|_| ToolFailure::Io)?;
    for entry in entries {
        let entry = entry.map_err(|_| ToolFailure::Io)?;
        let path = entry.path();
        if path.is_dir() {
            collect_json_files(&path, files)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            files.push(path);
        }
    }
    Ok(())
}

fn relative_path_string(root: &Path, file: &Path) -> Result<String, ToolFailure> {
    let relative = file.strip_prefix(root).map_err(|_| ToolFailure::Path)?;
    relative
        .to_str()
        .map(str::to_owned)
        .ok_or(ToolFailure::Path)
}

fn validate_relative_path(relative_path: &str) -> Result<(), ToolFailure> {
    let path = Path::new(relative_path);
    if path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        Ok(())
    } else {
        Err(ToolFailure::Path)
    }
}

fn parse(
    target: ParserTarget,
    semantic_profile: Option<SemanticProfile>,
    body: &str,
) -> ParserOutcome {
    let accepted = match target {
        ParserTarget::IssuerMetadata => parse_issuer_metadata(body, semantic_profile),
        ParserTarget::CredentialOffer => CredentialOffer::parse_json(body).is_ok(),
        ParserTarget::NonceResponse => NonceResponse::parse_json(body).is_ok(),
        ParserTarget::CredentialResponse => CredentialResponse::parse_json(body).is_ok(),
        ParserTarget::CredentialErrorResponse => CredentialErrorResponse::parse_json(body).is_ok(),
        ParserTarget::ProblemDetails => serde_json::from_str::<ProblemDetails>(body).is_ok(),
    };
    if accepted {
        ParserOutcome::Accepted
    } else {
        ParserOutcome::Rejected
    }
}

fn parse_issuer_metadata(body: &str, semantic_profile: Option<SemanticProfile>) -> bool {
    let Ok(metadata) = IssuerMetadata::parse_json(body) else {
        return false;
    };
    match semantic_profile {
        None => true,
        Some(SemanticProfile::EtsiReusePolicy) => metadata
            .credential_configurations_supported
            .values()
            .all(|configuration| {
                parse_credential_reuse_policy(configuration.credential_metadata.as_ref()).is_ok()
            }),
    }
}

fn update_totals(
    totals: &mut Totals,
    expectation: Expectation,
    outcome: ParserOutcome,
) -> Result<(), ToolFailure> {
    match outcome {
        ParserOutcome::Accepted => totals.accepted = increment(totals.accepted)?,
        ParserOutcome::Rejected => totals.rejected = increment(totals.rejected)?,
        ParserOutcome::Skipped => totals.skipped = increment(totals.skipped)?,
    }
    if outcome != ParserOutcome::Skipped {
        totals.compared = increment(totals.compared)?;
    }
    if expectation_matches(expectation, outcome) {
        totals.expectation_matches = increment(totals.expectation_matches)?;
    } else {
        totals.expectation_mismatches = increment(totals.expectation_mismatches)?;
    }
    Ok(())
}

fn expectation_matches(expectation: Expectation, outcome: ParserOutcome) -> bool {
    matches!(
        (expectation, outcome),
        (Expectation::Accept, ParserOutcome::Accepted)
            | (Expectation::Reject, ParserOutcome::Rejected)
            | (Expectation::NotApplicable, ParserOutcome::Skipped)
    )
}

fn increment(value: usize) -> Result<usize, ToolFailure> {
    value.checked_add(1).ok_or(ToolFailure::Io)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ToolFailure> {
    let body = serde_json::to_vec_pretty(value).map_err(|_| ToolFailure::Json)?;
    fs::write(path, body).map_err(|_| ToolFailure::Io)
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = digest_sha2_256(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest.as_bytes() {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
