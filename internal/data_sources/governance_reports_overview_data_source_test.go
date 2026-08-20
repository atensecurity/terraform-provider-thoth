package data_sources

import "testing"

func TestExtractOverviewMCPDeviationCounts(t *testing.T) {
	alerts, critical := extractOverviewMCPDeviationCounts(map[string]any{
		"kpi": map[string]any{
			"mcp_deviation_alerts":          int64(7),
			"mcp_critical_deviation_alerts": int64(2),
		},
	})

	if alerts != 7 || critical != 2 {
		t.Fatalf("counts = (%d,%d), want (7,2)", alerts, critical)
	}
}

func TestExtractOverviewMCPDeviationByTypeJSON(t *testing.T) {
	got := extractOverviewMCPDeviationByTypeJSON(map[string]any{
		"mcp_deviation_by_type": []any{
			map[string]any{"category": "mcp_vendor_deviation", "count": 3},
			map[string]any{"category": "mcp_egress_deviation", "count": 1},
		},
	})

	if got == "" || got == "[]" || got == "{}" {
		t.Fatalf("unexpected by-type json payload: %q", got)
	}
}
