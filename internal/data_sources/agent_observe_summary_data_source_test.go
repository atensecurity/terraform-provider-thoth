package data_sources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

func TestAgentObserveSummaryReadsTheReadinessVerdict(t *testing.T) {
	var gotPath, gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent_id": "billing agent", "days": 14, "observed": 312, "would_change": 4,
			"by_decision": map[string]any{"ALLOW": 308, "STEP_UP": 4},
			"top_rules":   []any{map[string]any{"key": "rule-refunds", "count": 4}},
			"examples":    []any{},
			"readiness": map[string]any{
				"ready": true, "mode": "observe",
				"checks": []any{map[string]any{"id": "days_observed", "passed": true, "detail": "9 days observed (needs 7)"}},
				"next":   "Ready to enforce.",
			},
		})
	}))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.GetAgentObserveSummary(context.Background(), "billing agent", 14)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/tenant-a/thoth/v1/agents/billing agent/observe-summary" || gotQuery != "days=14" {
		t.Fatalf("requested %s?%s", gotPath, gotQuery)
	}
	state := observeSummaryState(agentObserveSummaryModel{AgentID: types.StringValue("billing agent"), Days: types.Int64Value(14)}, result)
	if !state.ReadyToEnforce.ValueBool() || state.Mode.ValueString() != "observe" || state.Observed.ValueInt64() != 312 || state.WouldChange.ValueInt64() != 4 {
		t.Fatalf("state %+v", state)
	}
	if !strings.Contains(state.ReadinessChecks.ValueString(), `"days_observed"`) || !strings.Contains(state.TopRulesJSON.ValueString(), "rule-refunds") {
		t.Fatalf("json %s %s", state.ReadinessChecks.ValueString(), state.TopRulesJSON.ValueString())
	}

	// A server without readiness never reads as ready.
	state = observeSummaryState(agentObserveSummaryModel{}, map[string]any{"observed": 3})
	if state.ReadyToEnforce.ValueBool() || !state.Mode.IsNull() {
		t.Fatalf("missing readiness %+v", state)
	}
}
