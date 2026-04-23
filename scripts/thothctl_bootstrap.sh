#!/usr/bin/env bash
set -euo pipefail

THOTHCTL_BIN="${THOTHCTL_BIN:-thothctl}"
THOTH_JSON_OUTPUT="${THOTH_JSON_OUTPUT:-true}"
THOTH_TIMEOUT_SECONDS="${THOTH_TIMEOUT_SECONDS:-20}"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "error: required environment variable '${name}' is not set" >&2
    exit 1
  fi
}

require_env THOTH_GOVAPI_URL
require_env THOTH_TENANT_ID

if [[ -z "${THOTH_ADMIN_BEARER_TOKEN:-}" && -z "${THOTH_ADMIN_BEARER_TOKEN_FILE:-}" ]]; then
  echo "error: set THOTH_ADMIN_BEARER_TOKEN or THOTH_ADMIN_BEARER_TOKEN_FILE" >&2
  exit 1
fi

if ! command -v "${THOTHCTL_BIN}" >/dev/null 2>&1; then
  echo "error: '${THOTHCTL_BIN}' was not found in PATH" >&2
  exit 1
fi

args=(
  bootstrap
  --govapi-url "${THOTH_GOVAPI_URL}"
  --tenant-id "${THOTH_TENANT_ID}"
  --timeout-seconds "${THOTH_TIMEOUT_SECONDS}"
)

if [[ -n "${THOTH_ADMIN_BEARER_TOKEN:-}" ]]; then
  args+=(--auth-token "${THOTH_ADMIN_BEARER_TOKEN}")
fi

if [[ -n "${THOTH_ADMIN_BEARER_TOKEN_FILE:-}" ]]; then
  args+=(--auth-token-file "${THOTH_ADMIN_BEARER_TOKEN_FILE}")
fi

if [[ -n "${THOTH_COMPLIANCE_PROFILE:-}" ]]; then
  args+=(--compliance-profile "${THOTH_COMPLIANCE_PROFILE}")
fi

if [[ -n "${THOTH_SHADOW_LOW:-}" ]]; then
  args+=(--shadow-low "${THOTH_SHADOW_LOW}")
fi
if [[ -n "${THOTH_SHADOW_MEDIUM:-}" ]]; then
  args+=(--shadow-medium "${THOTH_SHADOW_MEDIUM}")
fi
if [[ -n "${THOTH_SHADOW_HIGH:-}" ]]; then
  args+=(--shadow-high "${THOTH_SHADOW_HIGH}")
fi
if [[ -n "${THOTH_SHADOW_CRITICAL:-}" ]]; then
  args+=(--shadow-critical "${THOTH_SHADOW_CRITICAL}")
fi

if [[ -n "${THOTH_WEBHOOK_URL:-}" ]]; then
  args+=(--webhook-url "${THOTH_WEBHOOK_URL}")
fi
if [[ -n "${THOTH_WEBHOOK_SECRET:-}" ]]; then
  args+=(--webhook-secret "${THOTH_WEBHOOK_SECRET}")
fi
if [[ -n "${THOTH_WEBHOOK_ENABLED:-}" ]]; then
  args+=(--webhook-enabled "${THOTH_WEBHOOK_ENABLED}")
fi
if [[ "${THOTH_TEST_WEBHOOK:-false}" == "true" ]]; then
  args+=(--test-webhook)
fi

if [[ -n "${THOTH_TOOL_RISK_OVERRIDES_CSV:-}" ]]; then
  IFS=',' read -r -a risk_overrides <<< "${THOTH_TOOL_RISK_OVERRIDES_CSV}"
  for override in "${risk_overrides[@]}"; do
    trimmed="$(echo "${override}" | xargs)"
    [[ -n "${trimmed}" ]] && args+=(--tool-risk-override "${trimmed}")
  done
fi

if [[ -n "${THOTH_MDM_PROVIDER:-}" ]]; then
  args+=(--mdm-provider "${THOTH_MDM_PROVIDER}")
  if [[ -n "${THOTH_MDM_NAME:-}" ]]; then
    args+=(--mdm-name "${THOTH_MDM_NAME}")
  fi
  if [[ -n "${THOTH_MDM_ENABLED:-}" ]]; then
    args+=(--mdm-enabled "${THOTH_MDM_ENABLED}")
  fi
  if [[ -n "${THOTH_MDM_CONFIG_FILE:-}" ]]; then
    args+=(--mdm-config-file "${THOTH_MDM_CONFIG_FILE}")
  fi
  if [[ "${THOTH_MDM_START_SYNC:-false}" == "true" ]]; then
    args+=(--start-sync)
  fi
fi

if [[ "${THOTH_JSON_OUTPUT}" == "true" ]]; then
  args+=(--json)
fi

redacted_args=("${args[@]}")
if [[ -n "${THOTH_ADMIN_BEARER_TOKEN:-}" ]]; then
  for i in "${!redacted_args[@]}"; do
    if [[ "${redacted_args[$i]}" == "${THOTH_ADMIN_BEARER_TOKEN}" ]]; then
      redacted_args[$i]="***REDACTED***"
    fi
  done
fi

echo "Running ${THOTHCTL_BIN} ${redacted_args[*]}"
"${THOTHCTL_BIN}" "${args[@]}"
