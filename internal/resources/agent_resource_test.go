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
	got := flattenAgent(map[string]any{"display_name": "", "owner_email": ""}, "agent", agentModel{OwnerEmail: types.StringNull()})
	if !got.OwnerEmail.IsNull() || got.DisplayName.ValueString() != "agent" {
		t.Fatalf("expected null owner and the agent ID as name, got %+v", got)
	}
}

// govapi before November 2026 answered GET /agents/{id} with activity fields
// only. This is that response, exactly as ThothAgentDetail serialised it for
// a fresh agent with no events. The apply must still match the plan.
func TestAgentApplyAgainstAGetWithoutRegistrationFields(t *testing.T) {
	var puts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			puts++
			_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": "clinic-scheduler", "display_name": "Clinic scheduler (AgentCore reference)", "registered": true})
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id": "clinic-scheduler", "last_seen": "0001-01-01T00:00:00Z", "total_calls": 0,
				"session_count": 0, "violations_24h": 0, "enforcement_mode": "enforce", "status": "active",
			})
		}
	}))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "trantor", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	r := &agentResource{client: c}
	scope := types.SetValueMust(types.StringType, []attr.Value{types.StringValue("read_schedule"), types.StringValue("book_appointment")})
	plan := agentModel{
		AgentID: types.StringValue("clinic-scheduler"), DisplayName: types.StringValue("Clinic scheduler (AgentCore reference)"),
		OwnerEmail: types.StringValue("n@atensecurity.com"), ApprovedScope: scope,
	}
	got, err := r.apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != plan.DisplayName || got.OwnerEmail != plan.OwnerEmail || !got.ApprovedScope.Equal(scope) {
		t.Fatalf("applied state differs from the plan: %+v", got)
	}
}

// When Thoth does return the registration, it is authoritative: drift shows.
func TestAgentFlattenTakesStoredRegistrationOverState(t *testing.T) {
	prior := agentModel{
		DisplayName: types.StringValue("old"), OwnerEmail: types.StringValue("old@example.com"),
		ApprovedScope: types.SetValueMust(types.StringType, []attr.Value{types.StringValue("a")}),
	}
	got := flattenAgent(map[string]any{"display_name": "new", "owner_email": "new@example.com", "approved_scope": []any{"b"}}, "agent", prior)
	if got.DisplayName.ValueString() != "new" || got.OwnerEmail.ValueString() != "new@example.com" ||
		!got.ApprovedScope.Equal(types.SetValueMust(types.StringType, []attr.Value{types.StringValue("b")})) {
		t.Fatalf("stored values must win: %+v", got)
	}
}
