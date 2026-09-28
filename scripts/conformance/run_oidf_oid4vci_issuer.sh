#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

suite_dir="${1:-}"
issuer_bin="${2:-}"
config_file="${3:-conformance/fixtures/oidf/openid4vci-issuer-haip-config.json}"
results_dir="${CONFORMANCE_RESULTS_DIR:-target/conformance-results}"
issuer_base_url="${OPENID4VCI_ISSUER_BASE_URL:-https://localhost.emobix.co.uk:9443/}"
issuer_healthcheck_base_url="${OPENID4VCI_ISSUER_HEALTHCHECK_BASE_URL:-$issuer_base_url}"
issuer_bind="${OPENID4VCI_ISSUER_BIND:-127.0.0.1:9443}"
plan_id="${OIDF_PLAN_ID:-oid4vci-1_0-issuer-haip-test-plan}"
plan_expression="${OIDF_ISSUER_PLAN_EXPRESSION:-${plan_id}[vci_authorization_code_flow_variant=wallet_initiated][credential_format=sd_jwt_vc]}"
executable_plan_id="${OIDF_EXECUTABLE_PLAN_ID:-${plan_expression%%[*}}"
suite_contract="${OIDF_SUITE_CONTRACT:-conformance/oidf/suite-contract.json}"
profile_matrix="${OIDF_PROFILE_MATRIX:-conformance/oidf/profile-matrix.json}"
module_inventory="${OIDF_MODULE_INVENTORY:-conformance/oidf/certification-module-inventory.json}"
provenance_assertion="${OIDF_ISSUER_PROVENANCE_ASSERTION:-scripts/conformance/assert_oidf_issuer_provenance.sh}"
mdoc_iaca_file="${OPENID4VCI_MDOC_IACA_FILE:-conformance/fixtures/oidf/openid4vci-conformance-mdoc-iaca.pem}"
suite_commit="${OIDF_SUITE_COMMIT:-}"
python_bin="${PYTHON:-python3}"
conformance_server="${CONFORMANCE_SERVER:-https://localhost:8443/}"
conformance_server_mtls="${CONFORMANCE_SERVER_MTLS:-https://localhost:8444/}"
oidf_alias="${OIDF_ALIAS:-openid4vci-haip-issuer}"
oidf_callback_base_url="${OPENID4VCI_OIDF_CALLBACK_BASE_URL:-}"
if [ -z "$oidf_callback_base_url" ]; then
  case "$conformance_server" in
    https://localhost:8443/ | https://localhost:8443)
      oidf_callback_base_url="https://localhost.emobix.co.uk:8443"
      ;;
    *)
      oidf_callback_base_url="$conformance_server"
      ;;
  esac
fi
source_repository_dir="${OPENID4VCI_SOURCE_REPOSITORY_DIR:-.}"
browser_driver_pid=""
issuer_pid=""
runtime_dir=""

cleanup() {
  if [ -n "$browser_driver_pid" ]; then
    kill "$browser_driver_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$issuer_pid" ]; then
    kill "$issuer_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$runtime_dir" ] && [ -d "$runtime_dir" ]; then
    rm -rf "$runtime_dir"
  fi
}
trap cleanup EXIT

if [ -z "$suite_dir" ] || [ -z "$issuer_bin" ]; then
  echo "usage: run_oidf_oid4vci_issuer.sh <conformance-suite-dir> <issuer-bin> [config-file]" >&2
  exit 64
fi

if [ "${OIDF_EXPECTED_SKIPS_FILE+x}" = "x" ]; then
  echo "expected skips are forbidden for complete conformance runs" >&2
  exit 64
fi

if [ ! -f "$suite_contract" ]; then
  echo "OIDF suite contract not found" >&2
  exit 66
fi

if [ ! -f "$profile_matrix" ]; then
  echo "OIDF profile matrix not found" >&2
  exit 66
fi

if [ ! -f "$module_inventory" ]; then
  echo "OIDF certification module inventory not found" >&2
  exit 66
fi
if [ ! -x "$provenance_assertion" ]; then
  echo "OIDF issuer provenance assertion is not executable" >&2
  exit 66
fi

for command_name in awk find git jq openssl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing required command: $command_name" >&2
    exit 69
  fi
done

profile_id="$(jq -er \
  --arg role "credential_issuer" \
  --arg plan_id "$plan_id" \
  --arg expression "$plan_expression" \
  '.profiles[] | select(
    .entity_under_test == $role and
    .plan_id == $plan_id and
    .plan_expression == $expression
  ) | .profile_id' \
  "$profile_matrix")" || {
  echo "issuer plan expression is not an allowlisted protocol profile" >&2
  exit 64
}
source_repository="$(jq -er '.source_repository | select(type == "string" and length > 0)' "$profile_matrix")" || {
  echo "profile matrix has no source repository" >&2
  exit 64
}
expected_module_count="$(jq -er \
  --arg profile_id "$profile_id" \
  '.profiles[]
   | select(.profile_id == $profile_id)
   | .expected_module_count
   | select(type == "number" and . > 0)' \
  "$profile_matrix")" || {
  echo "issuer protocol profile has no expected module count" >&2
  exit 64
}
suite_export_dir="$results_dir/$profile_id/suite-export"

if [ -z "$suite_commit" ]; then
  suite_commit="$(jq -er '.commit | select(type == "string" and length == 40)' "$suite_contract")"
fi

if [ ! -d "$suite_dir" ]; then
  echo "OIDF conformance suite directory not found" >&2
  exit 66
fi

if [ ! -x "$issuer_bin" ]; then
  echo "example issuer binary is not executable" >&2
  exit 66
fi

source_commit="$(git -C "$source_repository_dir" rev-parse --verify 'HEAD^{commit}')" || {
  echo "OpenID4VCI source commit is unavailable" >&2
  exit 66
}
if [ "${#source_commit}" -ne 40 ]; then
  echo "OpenID4VCI source commit is not a full SHA-1 commit identifier" >&2
  exit 66
fi
case "$source_commit" in
  *[!0-9a-f]*)
    echo "OpenID4VCI source commit is malformed" >&2
    exit 66
    ;;
esac
if [ -n "$(git -C "$source_repository_dir" status --porcelain --untracked-files=normal)" ]; then
  echo "OpenID4VCI source worktree is not clean" >&2
  exit 66
fi
issuer_binary_sha256="$(openssl dgst -sha256 "$issuer_bin" | awk '{print $NF}')" || {
  echo "example issuer binary digest could not be computed" >&2
  exit 66
}
if [ "${#issuer_binary_sha256}" -ne 64 ]; then
  echo "example issuer binary digest is malformed" >&2
  exit 66
fi
case "$issuer_binary_sha256" in
  *[!0-9a-f]*)
    echo "example issuer binary digest is malformed" >&2
    exit 66
    ;;
esac
"$provenance_assertion" \
  "$source_repository_dir" \
  "$issuer_bin" \
  "$source_commit" \
  "$issuer_binary_sha256"

if [ ! -f "$config_file" ]; then
  echo "OID4VCI issuer conformance config file not found" >&2
  exit 66
fi

mkdir -p "$results_dir/$profile_id"
rm -rf "$suite_export_dir"
mkdir -p "$suite_export_dir"
runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/openid4vci-oidf-issuer.XXXXXX")"
templated_config="$runtime_dir/oid4vci-issuer-config.templated.json"
runtime_config="$runtime_dir/oid4vci-issuer-config.json"
escaped_issuer_base_url="$(printf '%s' "$issuer_base_url" | sed 's/[&]/\\&/g')"
authorization_server="${issuer_base_url%/}"
escaped_authorization_server="$(printf '%s' "$authorization_server" | sed 's/[&]/\\&/g')"
sed \
  -e "s#{OPENID4VCI_ISSUER_BASE_URL}#$escaped_issuer_base_url#g" \
  -e "s#{OPENID4VCI_AUTHORIZATION_SERVER}#$escaped_authorization_server#g" \
  "$config_file" > "$templated_config"
credential_configuration_id="pid"
credential_trust_anchor="$(jq -er '.credential.trust_anchor_pem' "$templated_config")"
case "$plan_expression" in
  *"[credential_format=mdoc]"*)
    if [ ! -f "$mdoc_iaca_file" ]; then
      echo "mdoc IACA trust anchor not found" >&2
      exit 66
    fi
    credential_configuration_id="pid-mdoc"
    credential_trust_anchor="$(cat "$mdoc_iaca_file")"
    ;;
esac
jq \
  --arg alias "$oidf_alias" \
  --arg credential_configuration_id "$credential_configuration_id" \
  --arg credential_trust_anchor "$credential_trust_anchor" \
  '.alias = $alias
   | .vci.credential_configuration_id = $credential_configuration_id
   | .credential.trust_anchor_pem = $credential_trust_anchor' \
  "$templated_config" > "$runtime_config"

tls_cert="${OPENID4VCI_ISSUER_TLS_CERT:-}"
tls_key="${OPENID4VCI_ISSUER_TLS_KEY:-}"
case "$issuer_base_url" in
  https://*)
    if [ -z "$tls_cert" ]; then
      tls_cert="$runtime_dir/issuer-tls-cert.pem"
    fi
    if [ -z "$tls_key" ]; then
      tls_key="$runtime_dir/issuer-tls-key.pem"
    fi
    if [ ! -f "$tls_cert" ] || [ ! -f "$tls_key" ]; then
      openssl req \
        -x509 \
        -newkey rsa:2048 \
        -nodes \
        -keyout "$tls_key" \
        -out "$tls_cert" \
        -sha256 \
        -days 2 \
        -subj "/CN=localhost.emobix.co.uk" \
        -addext "subjectAltName=DNS:localhost.emobix.co.uk,DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1
    fi
    ;;
esac

check_issuer_endpoint() {
  if [ -n "$tls_cert" ]; then
    curl --fail --silent --show-error --max-time 10 --cacert "$tls_cert" "$1"
  else
    curl --fail --silent --show-error --max-time 10 "$1"
  fi
}

OPENID4VCI_ISSUER_BASE_URL="$issuer_base_url" \
OPENID4VCI_ISSUER_BIND="$issuer_bind" \
OPENID4VCI_ISSUER_TLS_CERT="$tls_cert" \
OPENID4VCI_ISSUER_TLS_KEY="$tls_key" \
OPENID4VCI_OAUTH_PRIMARY_REDIRECT_URI="${oidf_callback_base_url%/}/test/a/${oidf_alias}/callback" \
OPENID4VCI_OAUTH_SECONDARY_REDIRECT_URI="${oidf_callback_base_url%/}/test/a/${oidf_alias}/callback2" \
OPENID4VCI_OAUTH_SECONDARY_ALTERNATE_REDIRECT_URI="${oidf_callback_base_url%/}/test/a/${oidf_alias}/callback?dummy1=lorem&dummy2=ipsum" \
"$issuer_bin" &
issuer_pid="$!"
sleep 2

if ! kill -0 "$issuer_pid" >/dev/null 2>&1; then
  echo "example issuer exited before the conformance suite could connect" >&2
  exit 70
fi

metadata_url="${issuer_healthcheck_base_url%/}/.well-known/openid-credential-issuer"
if ! check_issuer_endpoint "$metadata_url" >/dev/null; then
  echo "example issuer metadata endpoint is not reachable" >&2
  exit 70
fi

scoped_metadata_url="${issuer_healthcheck_base_url%/}/.well-known/openid-credential-issuer/openid4vci/example-issuer"
if ! check_issuer_endpoint "$scoped_metadata_url" >/dev/null; then
  echo "example issuer path-scoped metadata endpoint is not reachable" >&2
  exit 70
fi

actual_suite_commit="$(git -C "$suite_dir" rev-parse HEAD)"
if [ "$actual_suite_commit" != "$suite_commit" ]; then
  echo "OIDF conformance suite commit mismatch" >&2
  exit 66
fi

printf '%s\n' "$actual_suite_commit" > "$results_dir/$profile_id/oidf-suite-revision.txt"
"$python_bin" scripts/conformance/discover_oidf_openid4vci.py \
  "$suite_dir" \
  "$results_dir/$profile_id/oidf-discovery" \
  --contract "$suite_contract"

if [ "${OPENID4VCI_OIDF_BROWSER_DRIVER:-1}" != "0" ]; then
  CONFORMANCE_SERVER="$conformance_server" \
  OIDF_PLAN_ID="$executable_plan_id" \
  OIDF_ALIAS="$oidf_alias" \
  OPENID4VCI_ISSUER_BASE_URL="$issuer_base_url" \
  OPENID4VCI_ISSUER_HEALTHCHECK_BASE_URL="$issuer_healthcheck_base_url" \
  OPENID4VCI_CREDENTIAL_ISSUER_URL="${issuer_base_url%/}/openid4vci/example-issuer/" \
  OPENID4VCI_CREDENTIAL_CONFIGURATION_ID="$credential_configuration_id" \
  "$python_bin" scripts/conformance/drive_oidf_browser_redirects.py &
  browser_driver_pid="$!"
fi

CONFORMANCE_SERVER="$conformance_server" \
CONFORMANCE_SERVER_MTLS="$conformance_server_mtls" \
OPENID4VCI_ISSUER_BASE_URL="$issuer_base_url" \
scripts/conformance/execute_oidf_test_plan.sh \
  "$suite_dir/scripts/run-test-plan.py" \
  "$suite_export_dir" \
  "$plan_expression" \
  "$runtime_config"

scripts/conformance/assert_oidf_results.sh \
  "$suite_export_dir" \
  "$expected_module_count" \
  "$module_inventory" \
  "$plan_expression" \
  "$oidf_alias"
scripts/conformance/redact_oidf_config.sh \
  "$runtime_config" \
  "$results_dir/$profile_id/oid4vci-issuer-config.redacted.json"

suite_export_count="$(find "$suite_export_dir" -maxdepth 1 -type f -name '*.zip' | wc -l | tr -d ' ')"
if [ "$suite_export_count" != "1" ]; then
  echo "OIDF suite export digest requires exactly one ZIP artifact" >&2
  exit 66
fi
suite_export_file="$(find "$suite_export_dir" -maxdepth 1 -type f -name '*.zip' -print)"
suite_export_sha256="$(openssl dgst -sha256 "$suite_export_file" | awk '{print $NF}')" || {
  echo "OIDF suite export digest could not be computed" >&2
  exit 66
}
if [ "${#suite_export_sha256}" -ne 64 ]; then
  echo "OIDF suite export digest is malformed" >&2
  exit 66
fi
case "$suite_export_sha256" in
  *[!0-9a-f]*)
    echo "OIDF suite export digest is malformed" >&2
    exit 66
    ;;
esac

# Re-evaluate mutable provenance immediately before summary creation. This
# prevents a source checkout or binary changed during a long suite run from
# being recorded as the clean deployment captured before execution.
"$provenance_assertion" \
  "$source_repository_dir" \
  "$issuer_bin" \
  "$source_commit" \
  "$issuer_binary_sha256"

jq -n \
  --arg source_repository "$source_repository" \
  --arg source_commit "$source_commit" \
  --arg profile_id "$profile_id" \
  --arg plan_id "$plan_id" \
  --arg plan_expression "$plan_expression" \
  --arg oidf_alias "$oidf_alias" \
  --arg result "passed" \
  --arg suite_commit "$actual_suite_commit" \
  --arg issuer_base_url "$issuer_base_url" \
  --arg issuer_config "oid4vci-issuer-config.redacted.json" \
  --arg issuer_binary_sha256 "$issuer_binary_sha256" \
  --arg suite_export_sha256 "$suite_export_sha256" \
  '{
    schema_version: 3,
    source_repository: $source_repository,
    source_commit: $source_commit,
    source_worktree_clean: true,
    profile_id: $profile_id,
    plan_id: $plan_id,
    plan_expression: $plan_expression,
    oidf_alias: $oidf_alias,
    result: $result,
    suite_commit: $suite_commit,
    issuer_base_url: $issuer_base_url,
    issuer_config: $issuer_config,
    issuer_binary_sha256: $issuer_binary_sha256,
    suite_export_sha256: $suite_export_sha256
  }' > "$results_dir/$profile_id/summary.json"
