// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Produces redacted parser-comparison evidence from pinned EUDI resources.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use openid4vci_types::{
    CredentialErrorResponse, CredentialOffer, CredentialResponse, IssuerMetadata, NonceResponse,
    ProblemDetails,
};
use reallyme_crypto::sha2::digest as digest_sha2_256;
use serde::Serialize;
use serde_json::Value;

const EXIT_INVALID_ARGS: u8 = 2;
const EXIT_IO: u8 = 3;
const EXIT_JSON: u8 = 4;
const EXIT_PATH: u8 = 5;

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
}

impl ToolFailure {
    const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidArgs => EXIT_INVALID_ARGS,
            Self::Io => EXIT_IO,
            Self::Json => EXIT_JSON,
            Self::Path => EXIT_PATH,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Expectation {
    Accept,
    Reject,
    NotApplicable,
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
    expectation: Expectation,
    outcome: ParserOutcome,
    expectation_matched: bool,
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
    fs::create_dir_all(&config.evidence_dir).map_err(|_| ToolFailure::Io)?;

    let mut files = Vec::new();
    collect_json_files(&config.resource_root, &mut files)?;
    files.sort();

    let mut totals = Totals::default();
    let mut resources = Vec::with_capacity(files.len());
    let mut comparisons = Vec::with_capacity(files.len());

    for file in files {
        totals.resources_seen = totals
            .resources_seen
            .checked_add(1)
            .ok_or(ToolFailure::Io)?;

        let body = fs::read_to_string(&file).map_err(|_| ToolFailure::Io)?;
        let relative_path = relative_path_string(&config.resource_root, &file)?;
        let sha256 = sha256_hex(body.as_bytes());
        let parser_target = classify_parser_target(&relative_path);
        let expectation = classify_expectation(&relative_path, parser_target, &body);
        let outcome = parser_target.map_or(ParserOutcome::Skipped, |target| parse(target, &body));

        update_totals(&mut totals, expectation, outcome)?;

        resources.push(FixtureResource {
            relative_path: relative_path.clone(),
            sha256: sha256.clone(),
            parser_target: parser_target.map(ParserTarget::wire_name),
            expectation,
        });
        comparisons.push(ComparisonRecord {
            relative_path,
            sha256,
            parser_target: parser_target.map(ParserTarget::wire_name),
            expectation,
            outcome,
            expectation_matched: expectation_matches(expectation, outcome),
        });
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
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
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

fn classify_parser_target(relative_path: &str) -> Option<ParserTarget> {
    let path = relative_path.to_ascii_lowercase();
    if path.contains("credential_issuer_metadata") || path.contains("openid-credential-issuer") {
        Some(ParserTarget::IssuerMetadata)
    } else if path.contains("credential_offer") || path.contains("sample_credential_offer") {
        Some(ParserTarget::CredentialOffer)
    } else if path.contains("cnonce") || path.contains("nonce") {
        Some(ParserTarget::NonceResponse)
    } else if path.contains("issuance_success_response")
        || path.contains("credential_response")
        || path.contains("deferredcredential")
        || path.contains("deferred_credential")
    {
        Some(ParserTarget::CredentialResponse)
    } else if path.contains("generic_error_response") || path.contains("error_response") {
        Some(ParserTarget::CredentialErrorResponse)
    } else if path.contains("problem_details") {
        Some(ParserTarget::ProblemDetails)
    } else {
        None
    }
}

fn classify_expectation(
    relative_path: &str,
    parser_target: Option<ParserTarget>,
    body: &str,
) -> Expectation {
    if parser_target.is_none() {
        return Expectation::NotApplicable;
    }

    let path = relative_path.to_ascii_lowercase();
    if path.contains("invalid_auth_server_hint") {
        return Expectation::Accept;
    }
    if path.contains("blank") && contains_blank_required_offer_value(body) {
        return Expectation::Reject;
    }
    if path.contains("invalid")
        || path.contains("negative")
        || path.contains("oversized")
        || path.contains("over_sized")
        || path.contains("zero_preferred")
        || path.contains("no_nonce_endpoint")
        || path.contains("contains_invalid")
        || path.contains("no_asymmetric_algs")
    {
        Expectation::Reject
    } else {
        Expectation::Accept
    }
}

fn contains_blank_required_offer_value(body: &str) -> bool {
    serde_json::from_str::<Value>(body)
        .ok()
        .is_some_and(|value| {
            let grants = value.get("grants").unwrap_or(&Value::Null);
            let authorization_code = grants.get("authorization_code").unwrap_or(&Value::Null);
            let pre_authorized = grants
                .get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
                .unwrap_or(&Value::Null);
            is_blank_json_string(authorization_code.get("issuer_state"))
                || is_blank_json_string(pre_authorized.get("pre-authorized_code"))
        })
}

fn is_blank_json_string(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|item| item.trim().is_empty())
}

fn parse(target: ParserTarget, body: &str) -> ParserOutcome {
    let accepted = match target {
        ParserTarget::IssuerMetadata => IssuerMetadata::parse_json(body).is_ok(),
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
