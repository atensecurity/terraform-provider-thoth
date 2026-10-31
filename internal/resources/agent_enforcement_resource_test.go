package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

type agentEnforcementAPI struct {
	mu   sync.Mutex
	puts []map[string]any
}

func (a *agentEnforcementAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant-a/thoth/agents/billing%2Fagent/enforcement-mode" && r.URL.RawPath != "/tenant-a/thoth/agents/billing%2Fagent/enforcement-mode" {
			t.Errorf("unexpected path %s (raw %s)", r.URL.Path, r.URL.RawPath)
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		current := map[string]any{"agent_id": "billing/agent", "enforcement_mode": "enforce", "high_risk_action": "hold", "after_decline": "raise", "after_decline_minutes": 30}
		if r.Method == http.MethodPut {
			body := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			a.puts = append(a.puts, body)
			current["enforcement_mode"], current["high_risk_action"] = body["enforcement_mode"], body["high_risk_action"]
			// As govapi answers: minutes only with raise.
			if value, ok := body["after_decline"]; ok {
				current["after_decline"] = value
				delete(current, "after_decline_minutes")
				if minutes, ok := body["after_decline_minutes"]; ok {
					current["after_decline_minutes"] = minutes
				}
			}
		}
		_ = json.NewEncoder(w).Encode(current)
	})
}

func newAgentEnforcementResource(t *testing.T, api *agentEnforcementAPI) *agentEnforcementResource {
	t.Helper()
	server := httptest.NewServer(api.handler(t))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	return &agentEnforcementResource{client: c}
}

func TestAgentEnforcementApplyEscapesTheAgentAndSendsBothChoices(t *testing.T) {
	api := &agentEnforcementAPI{}
	r := newAgentEnforcementResource(t, api)
	got, err := r.apply(context.Background(), agentEnforcementModel{
		AgentID: types.StringValue("billing/agent"), EnforcementMode: types.StringValue("observe"), HighRiskAction: types.StringValue("hold"),
		AfterDecline: types.StringValue("raise"), AfterDeclineMin: types.Int64Value(30),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.EnforcementMode.ValueString() != "observe" || got.HighRiskAction.ValueString() != "hold" || got.ID.ValueString() != "billing/agent" {
		t.Fatalf("unexpected state %+v", got)
	}
	if len(api.puts) != 1 || api.puts[0]["enforcement_mode"] != "observe" || api.puts[0]["high_risk_action"] != "hold" {
		t.Fatalf("unexpected request %+v", api.puts)
	}
}

func TestAgentEnforcementFlattenDefaultsToEnforce(t *testing.T) {
	got := flattenAgentEnforcement(map[string]any{}, "agent")
	if got.EnforcementMode.ValueString() != "enforce" || got.HighRiskAction.ValueString() != "hold" {
		t.Fatalf("empty responses read as enforce/hold, got %+v", got)
	}
}

func TestAgentEnforcementSendsAfterDecline(t *testing.T) {
	api := &agentEnforcementAPI{}
	r := newAgentEnforcementResource(t, api)
	got, err := r.apply(context.Background(), agentEnforcementModel{
		AgentID: types.StringValue("billing/agent"), EnforcementMode: types.StringValue("enforce"), HighRiskAction: types.StringValue("hold"),
		AfterDecline: types.StringValue("raise"), AfterDeclineMin: types.Int64Value(45),
	})
	if err != nil {
		t.Fatal(err)
	}
	if api.puts[0]["after_decline"] != "raise" || api.puts[0]["after_decline_minutes"] != float64(45) {
		t.Fatalf("unexpected request %+v", api.puts[0])
	}
	if got.AfterDecline.ValueString() != "raise" || got.AfterDeclineMin.ValueInt64() != 45 {
		t.Fatalf("unexpected state %+v", got)
	}

	// Stop and quarantine send no minutes, and the plan's value is kept.
	got, err = r.apply(context.Background(), agentEnforcementModel{
		AgentID: types.StringValue("billing/agent"), EnforcementMode: types.StringValue("enforce"), HighRiskAction: types.StringValue("hold"),
		AfterDecline: types.StringValue("stop"), AfterDeclineMin: types.Int64Value(30),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, sent := api.puts[1]["after_decline_minutes"]; sent || api.puts[1]["after_decline"] != "stop" {
		t.Fatalf("unexpected request %+v", api.puts[1])
	}
	if got.AfterDecline.ValueString() != "stop" || got.AfterDeclineMin.ValueInt64() != 30 {
		t.Fatalf("unexpected state %+v", got)
	}
}

func TestAgentEnforcementFlattenDefaultsToRaise(t *testing.T) {
	got := flattenAgentEnforcement(map[string]any{}, "agent")
	if got.AfterDecline.ValueString() != "raise" || got.AfterDeclineMin.ValueInt64() != 30 {
		t.Fatalf("empty responses read as raise for 30 minutes, got %+v", got)
	}
}
