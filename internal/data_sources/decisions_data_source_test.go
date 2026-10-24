package data_sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

// decisionsAPI serves total decisions in pages, like govapi's activity list.
func decisionsAPI(t *testing.T, total int, seen *[]map[string]string) *client.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant-a/thoth/v1/activity" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		q := map[string]string{}
		for key := range r.URL.Query() {
			q[key] = r.URL.Query().Get(key)
		}
		*seen = append(*seen, q)
		start, _ := strconv.Atoi(q["cursor"])
		limit, _ := strconv.Atoi(q["limit"])
		items := []any{}
		for i := start; i < total && i < start+limit; i++ {
			items = append(items, map[string]any{
				"id": fmt.Sprintf("decision:t-%d", i), "type": "decision", "at": "2026-10-24T10:00:00Z",
				"outcome": "blocked", "decision": "STEP_UP", "agent_id": "agent-a", "tool_name": "orders.delete",
				"reason_code": "rule_block", "hold": map[string]any{"status": "denied"},
				"resolution": map[string]any{"status": "denied", "by": "user_a"}, "link": "/activity",
			})
		}
		body := map[string]any{"items": items}
		if start+limit < total {
			body["next_cursor"] = strconv.Itoa(start + limit)
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCollectDecisionsPagesAndReportsTruncation(t *testing.T) {
	for _, tc := range []struct {
		total, max, want, requests int
		truncated                  bool
	}{
		{total: 3, max: 100, want: 3, requests: 1},
		{total: 250, max: 1000, want: 250, requests: 3},
		{total: 250, max: 120, want: 120, requests: 2, truncated: true},
		{total: 100, max: 100, want: 100, requests: 1},
		{total: 101, max: 100, want: 100, requests: 1, truncated: true},
	} {
		seen := []map[string]string{}
		c := decisionsAPI(t, tc.total, &seen)
		rows, truncated, err := collectDecisions(context.Background(), c, map[string]string{"filter": "blocked", "tool": "orders.delete"}, tc.max)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != tc.want || truncated != tc.truncated || len(seen) != tc.requests {
			t.Fatalf("%+v: got %d rows, truncated %v, %d requests", tc, len(rows), truncated, len(seen))
		}
		for _, q := range seen {
			if q["type"] != "decision" || q["filter"] != "blocked" || q["tool"] != "orders.delete" {
				t.Fatalf("filters not sent on every page: %v", q)
			}
		}
	}
}

func TestDecisionFromItemMapsHoldAndResolution(t *testing.T) {
	row := decisionFromItem(map[string]any{"id": "decision:t", "outcome": "blocked", "hold": map[string]any{"status": "denied"}, "resolution": map[string]any{"status": "denied"}})
	if row.ID.ValueString() != "decision:t" || row.HoldStatus.ValueString() != "denied" || row.Resolution.ValueString() != "denied" {
		t.Fatalf("row = %+v", row)
	}
	if !decisionFromItem(map[string]any{"id": "decision:a"}).ToolName.IsNull() {
		t.Fatal("a missing field is null, not an empty string")
	}
}
