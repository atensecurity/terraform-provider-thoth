# Changelog

All notable changes to `terraform-provider-thoth` are documented in this file.

## 0.1.6 - 2026-05-10

### Added

- Explicit regulatory regime support in governance surfaces:
  - `regulatory_regimes` on `thoth_governance_settings`
  - `regulatory_regimes` and effective regulatory profile fields in tenant settings reads
- Updated onboarding guidance to use explicit regulatory regime declaration
  (with GovAPI fallback behavior documented).

### Changed

- Policy bundle workflows are now mode-based (`enforce` / `observe`) and no longer
  expose an environment selector on customer-facing bundle surfaces.
- Refreshed public examples/docs/runbooks to target provider release `~> 0.1.6`.

### Breaking Changes

- Removed `environment` from:
  - `thoth_policy_bundle` resource
  - `thoth_policy_bundles` data source
  - `thoth_effective_policy_bundles` data source

## 0.1.5 - 2026-05-10

### Added

- Billing management surface for customer-visible overage and invoice previews:
  - `thoth_billing_overage_cap` resource
  - `thoth_billing_estimate` data source
  - `thoth_billing_credit_bank` data source
- Extended billing data source outputs for reconciliation/reporting, including
  compliance receipts, low-balance alerts, FIFO credit burn details, and
  detailed line-item totals.
- Deterministic behavioral control fields on pack assignment resources:
  `mismatch_boost`, `delegation_boost`, `trust_floor`, and
  `critical_threshold`.

### Changed

- Updated provider client and docs to reflect Aten-managed pricing with
  customer-controlled overage caps and estimate workflows.
- Updated bootstrap helper scripts and provider docs for newer billing and
  deterministic-control flows.
- Updated `golang.org/x/net` dependency to `v0.53.0`.

### Compatibility

- No breaking schema removals in this release.
- Existing auth methods (`THOTH_API_KEY` and bearer token) remain supported.

## 0.1.4 - 2026-05-06

### Added

- `thoth_api_keys` data source for API key inventory queries with scope and active-state filtering.
- New scope-specific API key resources:
  `thoth_fleet_api_key`, `thoth_endpoint_api_key`, `thoth_agent_api_key`.
- New focused tenant settings resources:
  `thoth_governance_settings`, `thoth_webhook_settings`, `thoth_siem_settings`,
  and `thoth_pam_settings`.
- Fleet lifecycle coverage:
  `thoth_fleet` resource plus `thoth_fleet`, `thoth_fleets`, `thoth_endpoints`, and
  `thoth_endpoint_stats` data sources.
- Governance evidence read coverage:
  `thoth_evidence_bundle`, `thoth_evidence_chain`, and `thoth_evidence_verify`
  data sources.
- MDM and browser inventory coverage:
  `thoth_mdm_providers`, `thoth_browser_providers`, `thoth_browser_policies`, and
  `thoth_browser_enrollments` data sources.

### Removed

- Deprecated legacy API key resource `thoth_api_key`.
  Use `thoth_fleet_api_key`, `thoth_endpoint_api_key`, and `thoth_agent_api_key`.
- Deprecated legacy umbrella settings resource `thoth_tenant_settings`.
  Use `thoth_governance_settings`, `thoth_webhook_settings`,
  `thoth_siem_settings`, and `thoth_pam_settings`.

### Changed

- Provider examples and docs now target `~> 0.1.4` for next-release guidance.
- Provider registry docs include expanded authentication guidance with explicit
  org-scoped `THOTH_API_KEY` requirements and auth precedence rules.
- Updated examples, acceptance stubs, and docs to remove usage of removed resources.
- `thoth_pack_assignment` and `thoth_pack_assignment_bulk` remain separate
  lifecycle resources (no merge or schema change).
- `thoth_pack_assignment` and `thoth_pack_assignment_bulk` now expose first-class
  deterministic control fields (`mismatch_boost`, `delegation_boost`,
  `trust_floor`, `critical_threshold`) that merge into
  `overrides.behavioral_controls` / `overrides_by_pack.behavioral_controls`.
- MDM and browser provider/policy/enrollment resources remain unified multi-provider
  resources pending provider-specific typed API contracts.

### Compatibility

- This release intentionally removes deprecated resources because the provider
  is not yet in production customer use.

## 0.1.3 - 2026-05-05

### Added

- Org-level API key auth in provider configuration (`org_api_key`, `org_api_key_file`).
- `THOTH_API_KEY` environment-variable fallback for non-interactive CI/CD workflows.

### Changed

- Provider auth documentation now shows both supported methods side-by-side:
  org API key and admin bearer token.
- Examples and registry docs now prefer org API keys for automation use cases.

### Compatibility

- Existing bearer token auth remains supported
  (`admin_bearer_token`, `admin_bearer_token_file`).
- No breaking schema changes in this release.

## 0.1.2 - 2026-05-03

### Changed

- Stabilized provider packaging and release pipeline for Terraform Registry publication.
- Updated generated docs and schema snapshots for consistency across resources and data sources.

## 0.1.1 - 2026-05-02

### Added

- Signed `v0.1.1` release artifacts for Terraform Registry distribution.
- Initial complete Terraform Registry docs set for provider, resources, and data sources.

### Changed

- Updated MDM and browser resource schema fields from `provider` to `provider_name`
  to satisfy framework reserved-attribute constraints.
- Clarified release workflow examples and version validation messaging for stable and RC tags.
