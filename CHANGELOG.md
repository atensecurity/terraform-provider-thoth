# Changelog

All notable changes to `terraform-provider-thoth` are documented in this file.

## 0.1.4 - 2026-05-06

### Added

- `thoth_api_keys` data source for API key inventory queries with scope and active-state filtering.
- New scope-specific API key resources:
  `thoth_fleet_api_key`, `thoth_endpoint_api_key`, `thoth_agent_api_key`.
- Fleet lifecycle coverage:
  `thoth_fleet` resource plus `thoth_fleet`, `thoth_fleets`, `thoth_endpoints`, and
  `thoth_endpoint_stats` data sources.
- Governance evidence read coverage:
  `thoth_evidence_bundle`, `thoth_evidence_chain`, and `thoth_evidence_verify`
  data sources.
- MDM and browser inventory coverage:
  `thoth_mdm_providers`, `thoth_browser_providers`, `thoth_browser_policies`, and
  `thoth_browser_enrollments` data sources.

### Changed

- Provider examples and docs now target `~> 0.1.4` for next-release guidance.
- Provider registry docs include expanded authentication guidance with explicit
  org-scoped `THOTH_API_KEY` requirements and auth precedence rules.
- `thoth_api_key` now rejects `organization` scope creation and recommends
  out-of-band org key creation via `thothctl`.
- `thoth_api_key` scope-driven creation is deprecated in favor of dedicated
  scoped resources.

### Compatibility

- No breaking schema changes in this release.

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
