package data_sources

import "testing"

func TestExtractExecutiveMCPDeviationCounts(t *testing.T) {
	alerts, critical := extractExecutiveMCPDeviationCounts(map[string]any{
		"kpis": map[string]any{
			"mcp_deviation_alerts":          11,
			"mcp_critical_deviation_alerts": 4,
		},
	})

	if alerts != 11 || critical != 4 {
		t.Fatalf("counts = (%d,%d), want (11,4)", alerts, critical)
	}
}
