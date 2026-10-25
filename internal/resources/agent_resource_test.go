package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

// agentAPI stores what /register receives and returns it from GET, as govapi
// does (agent_configs), including the display-name default.
type agentAPI struct {
	mu     sync.Mutex
	puts   []map[string]any
	record map[string]any
}

func (a *agentAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		switch {
		case r.Method == http.MethodPut && r.URL.EscapedPath() == "/tenant-a/thoth/agents/billing%2Fagent/register":
			body := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			a.puts = append(a.puts, body)
			if body["display_name"] == "" {
				body["display_name"] = "billing/agent"
			}
			a.record = map[string]any{"agent_id": "billing/agent", "display_name": body["display_name"], "owner_email": body["owner_email"], "approved_scope": body["approved_scope"], "status": "active"}
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case r.Method == http.MethodGet && r.URL.EscapedPath() == "/tenant-a/thoth/agents/billing%2Fagent":
			if a.record == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(a.record)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.EscapedPath())
			w.WriteHeader(http.StatusTeapot)
		}
	})
}

func newAgentResourceForTest(t *testing.T, api *agentAPI) *agentResource {
	t.Helper()
	server := httptest.NewServer(api.handler(t))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	return &agentResource{client: c}
}

func TestAgentRegistersWithoutAModeAndReadsBack(t *testing.T) {
	api := &agentAPI{}
	r := newAgentResourceForTest(t, api)
	scope := types.SetValueMust(types.StringType, []attr.Value{types.StringValue("orders.read"), types.StringValue("customers.read")})
	got, err := r.apply(context.Background(), agentModel{
		AgentID: types.StringValue("billing/agent"), DisplayName: types.StringUnknown(), OwnerEmail: types.StringValue("owner@example.com"), ApprovedScope: scope,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(api.puts) != 1 {
		t.Fatalf("expected one registration, got %+v", api.puts)
	}
	if _, sent := api.puts[0]["enforcement_mode"]; sent {
		t.Fatalf("registration must not set the mode; thoth_agent_enforcement does: %+v", api.puts[0])
	}
	if got.DisplayName.ValueString() != "billing/agent" || got.Status.ValueString() != "active" || got.OwnerEmail.ValueString() != "owner@example.com" {
		t.Fatalf("unexpected state %+v", got)
	}
	if !got.ApprovedScope.Equal(types.SetValueMust(types.StringType, []attr.Value{types.StringValue("customers.read"), types.StringValue("orders.read")})) {
		t.Fatalf("approved scope did not read back: %v", got.ApprovedScope)
	}
}

func TestAgentFlattenKeepsAnUnsetOwnerNull(t *testing.T) {
	got := flattenAgent(map[string]any{"display_name": "", "owner_email": ""}, "agent", types.StringNull())
	if !got.OwnerEmail.IsNull() || got.DisplayName.ValueString() != "agent" {
		t.Fatalf("expected null owner and the agent ID as name, got %+v", got)
	}
}
