---
page_title: "thoth_report_data Data Source - thoth"
subcategory: "Governance"
description: |
  Reads unified AIRS report snapshots (latest/by-id) and exposes canonical JSON plus metadata.
---

# thoth_report_data (Data Source)

Reads unified AIRS report snapshots (latest/by-id) and exposes canonical JSON plus metadata.

## Example Usage

```terraform
data "thoth_report_data" "latest_audit" {
  cadence     = "7d"
  report_type = "governance"
}
```

## Argument Reference

- `report_id` (String) Optional report ID. Defaults to latest completed report.
- `cadence` (String) Optional cadence filter (`7d`, `30d`, `custom`).
- `status` (String) Optional status filter when resolving latest (`PENDING`, `COMPLETED`, `FAILED`).
- `report_type` (String) Optional projection (`full`, `metadata`, `governance`, `economic`, `dlp`, `forensic`, `post_approval_gap`).
- `agent_id` (String) Optional consumer-side selector for downstream tool workflows.

## Attribute Reference

- `report_id` (String) Resolved report ID.
- `response_json` (String) Canonical report payload as JSON.
- `metadata_json` (String) Metadata projection as JSON.
