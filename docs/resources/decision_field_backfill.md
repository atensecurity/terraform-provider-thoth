---
page_title: "thoth_decision_field_backfill Resource"
subcategory: "Governance"
description: |-
  Backfills normalized decision evidence fields for Thoth behavioral events.
---

# thoth_decision_field_backfill

Triggers `POST /:tenant-id/thoth/governance/backfill-decision-fields` and stores execution stats.

## Example Usage

```terraform
resource "thoth_decision_field_backfill" "r8" {
  trigger                = "2026-05-r8"
  limit                  = 500
  window_hours           = 720
  include_blocked_events = true
  dry_run                = false
}
```
