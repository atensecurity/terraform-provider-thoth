# Changelog

All notable changes to `terraform-provider-thoth` are documented in this file.

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
