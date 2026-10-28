package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

// policyAPI stands in for GovAPI's /:tenant-id/thoth/policies routes.
type policyAPI struct {
	mu       sync.Mutex
	policies map[string]map[string]any // id -> rule
	queries  []string                  // env query of each request
	updates  []map[string]any
}

func (a *policyAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		env := r.URL.Query().Get("env")
		a.queries = append(a.queries, env)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/tenant-a/thoth/policies":
			out := []any{}
			for _, p := range a.policies {
				if p["environment"] == env {
					out = append(out, p)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"policies": out, "total": len(out), "environment": env})
		case r.Method == http.MethodPost && r.URL.Path == "/tenant-a/thoth/policies":
			body := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			body["id"], body["status"], body["environment"] = "6ae1441907c1c31e7e44ca5a", "pending", env
			a.policies[body["id"].(string)] = body
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(body)
		case r.Method == http.MethodPut:
			body := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			a.updates = append(a.updates, body)
			id := r.URL.Path[len("/tenant-a/thoth/policies/"):]
			for k, v := range body {
				a.policies[id][k] = v
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"updated": true})
		case r.Method == http.MethodDelete:
			delete(a.policies, r.URL.Path[len("/tenant-a/thoth/policies/"):])
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func newPolicyClient(t *testing.T, api *policyAPI) *client.Client {
	t.Helper()
	server := httptest.NewServer(api.handler(t))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func policyPlan(rulesJSON string) policyResourceModel {
	plan := policyResourceModel{
		Environment: types.StringValue("prod"), Name: types.StringValue("Hold deletes"), Description: types.StringNull(),
		Type: types.StringValue("scope"), Enforcement: types.StringValue("review"), Enabled: types.BoolValue(true),
		AppliedTo: types.ListValueMust(types.StringType, []attr.Value{types.StringValue("agent-a")}), RulesJSON: types.StringNull(),
	}
	if rulesJSON != "" {
		plan.RulesJSON = types.StringValue(rulesJSON)
	}
	return plan
}

func TestPolicyPayloadSendsTheEditedFields(t *testing.T) {
	payload, err := policyPayload(context.Background(), policyPlan(`{"conditions": {"action_class": ["delete"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if payload["name"] != "Hold deletes" || payload["type"] != "scope" || payload["enforcement"] != "review" {
		t.Fatalf("payload %v", payload)
	}
	if applied := payload["applied_to"].([]string); len(applied) != 1 || applied[0] != "agent-a" {
		t.Fatalf("applied_to %v", payload["applied_to"])
	}
	if _, ok := payload["rules"].(map[string]any)["conditions"]; !ok {
		t.Fatalf("rules %v", payload["rules"])
	}
	for _, field := range []string{"status", "reviewed_by", "created_by"} {
		if _, ok := payload[field]; ok {
			t.Fatalf("%s must not be sent on create or update", field)
		}
	}
	if _, err := policyPayload(context.Background(), policyPlan(`["not", "an", "object"]`)); err == nil {
		t.Fatal("rules_json must be an object")
	}
}

func TestPolicyClientNamesTheEnvironmentAndReadsByList(t *testing.T) {
	api := &policyAPI{policies: map[string]map[string]any{}}
	c := newPolicyClient(t, api)
	created, err := c.CreatePolicy(context.Background(), "dev", map[string]any{"name": "R", "type": "scope", "enforcement": "block"})
	if err != nil || created["id"] == "" {
		t.Fatalf("create %v %v", created, err)
	}
	row, err := c.GetPolicy(context.Background(), "6ae1441907c1c31e7e44ca5a", "dev")
	if err != nil || row["name"] != "R" {
		t.Fatalf("get %v %v", row, err)
	}
	if _, err := c.GetPolicy(context.Background(), "6ae1441907c1c31e7e44ca5a", "prod"); !client.IsNotFound(err) {
		t.Fatalf("a rule in dev is not found in prod: %v", err)
	}
	if err := c.UpdatePolicy(context.Background(), "6ae1441907c1c31e7e44ca5a", "dev", map[string]any{"status": "disabled"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePolicy(context.Background(), "6ae1441907c1c31e7e44ca5a", "dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPolicy(context.Background(), "6ae1441907c1c31e7e44ca5a", "dev"); !client.IsNotFound(err) {
		t.Fatalf("deleted rule: %v", err)
	}
	for i, env := range api.queries {
		if env == "" {
			t.Fatalf("request %d sent no env", i)
		}
	}
}

func TestFlattenPolicyKeepsFormattingAndReportsStatus(t *testing.T) {
	configured := "{\n  \"conditions\": {\"window\": \"1h\", \"action_class\": [\"delete\"]}\n}"
	row := map[string]any{
		"id": "abc", "environment": "prod", "name": "Hold deletes", "type": "scope", "enforcement": "review",
		"status": "pending", "applied_to": []any{"agent-a"},
		"rules": map[string]any{"conditions": map[string]any{"action_class": []any{"delete"}, "window": "1h"}},
	}
	next, diags := flattenPolicy(context.Background(), row, policyPlan(configured), "tenant-a")
	if diags.HasError() {
		t.Fatal(diags)
	}
	if next.RulesJSON.ValueString() != configured {
		t.Fatalf("formatting showed as drift: %s", next.RulesJSON.ValueString())
	}
	if next.ID.ValueString() != "prod/abc" || next.Status.ValueString() != "pending" || !next.Enabled.ValueBool() {
		t.Fatalf("state %+v", next)
	}

	// A change made elsewhere shows as drift, and a disabled rule as enabled = false.
	row["rules"] = map[string]any{"conditions": map[string]any{"action_class": []any{"read"}}}
	row["status"] = "disabled"
	next, _ = flattenPolicy(context.Background(), row, policyPlan(configured), "tenant-a")
	if next.RulesJSON.ValueString() == configured || next.Enabled.ValueBool() {
		t.Fatalf("state %+v", next)
	}
	// A rejected rule is reported, and stays enabled in configuration terms.
	row["status"] = "rejected"
	next, _ = flattenPolicy(context.Background(), row, policyPlan(""), "tenant-a")
	if next.Status.ValueString() != "rejected" {
		t.Fatalf("status %s", next.Status.ValueString())
	}
}

func TestPolicyImportNeedsEnvironmentAndID(t *testing.T) {
	r := &policyResource{}
	for id, ok := range map[string]bool{"prod/abc": true, "dev/abc": true, "abc": false, "staging/abc": false, "prod/": false} {
		resp := &resource.ImportStateResponse{State: emptyPolicyState(t)}
		r.ImportState(context.Background(), resource.ImportStateRequest{ID: id}, resp)
		if resp.Diagnostics.HasError() == ok {
			t.Errorf("%q: ok=%v, diagnostics %v", id, ok, resp.Diagnostics)
		}
	}
}

// emptyPolicyState is a null state with the resource's schema, as import starts from.
func emptyPolicyState(t *testing.T) tfsdk.State {
	t.Helper()
	schemaResp := &resource.SchemaResponse{}
	(&policyResource{}).Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatal(schemaResp.Diagnostics)
	}
	return tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil)}
}
