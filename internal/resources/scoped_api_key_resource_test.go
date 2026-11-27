package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

func keyResource(scope string) *scopedAPIKeyResource {
	switch scope {
	case apiKeyScopeFleet:
		return NewFleetAPIKeyResource().(*scopedAPIKeyResource)
	case apiKeyScopeAgent:
		return NewAgentAPIKeyResource().(*scopedAPIKeyResource)
	}
	return NewEndpointAPIKeyResource().(*scopedAPIKeyResource)
}

func keySchema(t *testing.T, r *scopedAPIKeyResource) *resource.SchemaResponse {
	t.Helper()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	return resp
}

func strList(vals ...string) tftypes.Value {
	items := make([]tftypes.Value, 0, len(vals))
	for _, v := range vals {
		items = append(items, tftypes.NewValue(tftypes.String, v))
	}
	return tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, items)
}

func strSet(vals ...string) tftypes.Value {
	items := make([]tftypes.Value, 0, len(vals))
	for _, v := range vals {
		items = append(items, tftypes.NewValue(tftypes.String, v))
	}
	return tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, items)
}

// keyObject fills every attribute of the schema, null unless given.
func keyObject(t *testing.T, r *scopedAPIKeyResource, given map[string]tftypes.Value) (tftypes.Value, *resource.SchemaResponse) {
	t.Helper()
	sch := keySchema(t, r)
	typ := sch.Schema.Type().TerraformType(context.Background()).(tftypes.Object)
	values := map[string]tftypes.Value{}
	for name, at := range typ.AttributeTypes {
		values[name] = tftypes.NewValue(at, nil)
	}
	for name, v := range given {
		if _, ok := typ.AttributeTypes[name]; !ok {
			t.Fatalf("schema has no attribute %q", name)
		}
		values[name] = v
	}
	return tftypes.NewValue(typ, values), sch
}

func validate(t *testing.T, r *scopedAPIKeyResource, given map[string]tftypes.Value) *resource.ValidateConfigResponse {
	t.Helper()
	raw, sch := keyObject(t, r, given)
	resp := &resource.ValidateConfigResponse{}
	r.ValidateConfig(context.Background(), resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: sch.Schema, Raw: raw}}, resp)
	return resp
}

func str(s string) tftypes.Value { return tftypes.NewValue(tftypes.String, s) }

func TestOnlyTheEndpointKeyHasTheGatewayAttributes(t *testing.T) {
	for _, attr := range []string{"kind", "allowed_agents", "allowed_tools"} {
		if _, ok := keySchema(t, keyResource(apiKeyScopeEndpoint)).Schema.Attributes[attr]; !ok {
			t.Errorf("thoth_endpoint_api_key lacks %s", attr)
		}
		for _, scope := range []string{apiKeyScopeFleet, apiKeyScopeAgent} {
			if _, ok := keySchema(t, keyResource(scope)).Schema.Attributes[attr]; ok {
				t.Errorf("%s key has %s", scope, attr)
			}
		}
	}
}

func TestGatewayAttributesRequireReplace(t *testing.T) {
	sch := keySchema(t, keyResource(apiKeyScopeEndpoint)).Schema
	for _, attr := range []string{"kind", "allowed_agents", "allowed_tools"} {
		var mods []string
		switch v := sch.Attributes[attr].(type) {
		case schema.StringAttribute:
			for _, m := range v.PlanModifiers {
				mods = append(mods, m.Description(context.Background()))
			}
		case schema.SetAttribute:
			for _, m := range v.PlanModifiers {
				mods = append(mods, m.Description(context.Background()))
			}
		}
		if len(mods) != 1 || !strings.Contains(mods[0], "recreate") {
			t.Errorf("%s does not require replace: %v", attr, mods)
		}
	}
}

func TestValidateConfigGatewayKey(t *testing.T) {
	good := map[string]tftypes.Value{
		"scope_target_id": str("ep-1"),
		"permissions":     strList("execute"),
		"kind":            str("mcp_gateway"),
		"allowed_agents":  strSet("agent-a"),
		"allowed_tools":   strSet("metabase__run_query"),
	}
	with := func(over map[string]tftypes.Value) map[string]tftypes.Value {
		out := map[string]tftypes.Value{}
		for k, v := range good {
			out[k] = v
		}
		for k, v := range over {
			out[k] = v
		}
		return out
	}
	cases := map[string]struct {
		cfg     map[string]tftypes.Value
		wantErr string
	}{
		"valid gateway":       {good, ""},
		"plain key":           {map[string]tftypes.Value{"scope_target_id": str("ep-1"), "permissions": strList("read", "execute")}, ""},
		"missing agents":      {with(map[string]tftypes.Value{"allowed_agents": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, nil)}), "allowed_agents"},
		"missing tools":       {with(map[string]tftypes.Value{"allowed_tools": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, nil)}), "allowed_tools"},
		"empty agents":        {with(map[string]tftypes.Value{"allowed_agents": strSet()}), "non-empty"},
		"bad tool":            {with(map[string]tftypes.Value{"allowed_tools": strSet("run_query")}), "<upstream>__<tool>"},
		"short prefix":        {with(map[string]tftypes.Value{"allowed_tools": strSet("me*")}), "at least 3"},
		"star agent":          {with(map[string]tftypes.Value{"allowed_agents": strSet("agent-*")}), "exact agent ids"},
		"read permission":     {with(map[string]tftypes.Value{"permissions": strList("read", "execute")}), "execute permission only"},
		"unknown kind":        {with(map[string]tftypes.Value{"kind": str("other")}), "mcp_gateway"},
		"lists without kind":  {map[string]tftypes.Value{"permissions": strList("execute"), "allowed_agents": strSet("agent-a")}, "only with kind"},
		"tools without kind":  {map[string]tftypes.Value{"permissions": strList("execute"), "allowed_tools": strSet("up__tool")}, "only with kind"},
		"unknown list values": {with(map[string]tftypes.Value{"allowed_tools": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, tftypes.UnknownValue)}), ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resp := validate(t, keyResource(apiKeyScopeEndpoint), tc.cfg)
			if tc.wantErr == "" {
				if resp.Diagnostics.HasError() {
					t.Fatalf("unexpected error: %v", resp.Diagnostics)
				}
				return
			}
			if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), tc.wantErr) {
				t.Fatalf("want an error containing %q, got %v", tc.wantErr, resp.Diagnostics)
			}
		})
	}
}

type keyAPI struct {
	mu       sync.Mutex
	creates  []map[string]any
	listRows []any
	response map[string]any
}

func (a *keyAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/thoth/api-keys"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			a.creates = append(a.creates, body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(a.response)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/thoth/api-keys"):
			_ = json.NewEncoder(w).Encode(map[string]any{"api_keys": a.listRows})
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	})
}

func keyResourceWithAPI(t *testing.T, scope string, api *keyAPI) *scopedAPIKeyResource {
	t.Helper()
	server := httptest.NewServer(api.handler())
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	r := keyResource(scope)
	r.client = c
	r.tenantID = "tenant-a"
	return r
}

func TestCreateGatewayKeySendsKindAndSortedLists(t *testing.T) {
	api := &keyAPI{response: map[string]any{
		"key_id": "key-1", "api_key": "thoth_secret_value", "prefix": "thoth_ab",
		"created_at": "2026-11-26T00:00:00Z", "expires_at": "2026-11-26T01:00:00Z",
		"kind": "mcp_gateway", "allowed_agents": []any{"agent-a", "agent-b"}, "allowed_tools": []any{"github__*", "metabase__run"},
	}}
	r := keyResourceWithAPI(t, apiKeyScopeEndpoint, api)
	raw, sch := keyObject(t, r, map[string]tftypes.Value{
		"scope_target_id": str("ep-1"),
		"permissions":     strList("execute"),
		"kind":            str("mcp_gateway"),
		"allowed_agents":  strSet("Agent-B", "agent-a", "AGENT-A"),
		"allowed_tools":   strSet("Metabase__Run", "github__*"),
	})
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: sch.Schema, Raw: tftypes.NewValue(sch.Schema.Type().TerraformType(context.Background()), nil)}}
	r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan{Schema: sch.Schema, Raw: raw}}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	body := api.creates[0]
	if body["kind"] != "mcp_gateway" || body["scope_level"] != "endpoint" {
		t.Fatalf("unexpected request %+v", body)
	}
	if !reflect.DeepEqual(body["allowed_agents"], []any{"agent-a", "agent-b"}) || !reflect.DeepEqual(body["allowed_tools"], []any{"github__*", "metabase__run"}) {
		t.Fatalf("lists were not normalised: %+v", body)
	}
	var state endpointAPIKeyModel
	if d := resp.State.Get(context.Background(), &state); d.HasError() {
		t.Fatal(d)
	}
	if state.APIKey.ValueString() != "thoth_secret_value" || state.Kind.ValueString() != "mcp_gateway" {
		t.Fatalf("unexpected state %+v", state)
	}
	// The configured spelling is kept, so the plan after apply is empty.
	if got := setStrings(state.AllowedAgents); len(got) != 3 {
		t.Fatalf("state should keep the configured set, got %v", got)
	}
}

func TestCreateOrdinaryKeySendsNoGatewayFields(t *testing.T) {
	api := &keyAPI{response: map[string]any{"key_id": "key-1", "api_key": "k", "prefix": "p"}}
	r := keyResourceWithAPI(t, apiKeyScopeEndpoint, api)
	raw, sch := keyObject(t, r, map[string]tftypes.Value{"scope_target_id": str("ep-1"), "permissions": strList("read")})
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: sch.Schema, Raw: tftypes.NewValue(sch.Schema.Type().TerraformType(context.Background()), nil)}}
	r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan{Schema: sch.Schema, Raw: raw}}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	for _, k := range []string{"kind", "allowed_agents", "allowed_tools"} {
		if _, ok := api.creates[0][k]; ok {
			t.Fatalf("an ordinary key sent %s: %+v", k, api.creates[0])
		}
	}
}

func TestCreateRefusesAnInvalidGatewayKeyBeforeTheRequest(t *testing.T) {
	api := &keyAPI{response: map[string]any{"key_id": "key-1"}}
	r := keyResourceWithAPI(t, apiKeyScopeEndpoint, api)
	raw, sch := keyObject(t, r, map[string]tftypes.Value{
		"scope_target_id": str("ep-1"), "permissions": strList("execute"), "kind": str("mcp_gateway"),
		"allowed_agents": strSet("agent-a"), "allowed_tools": strSet("*"),
	})
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: sch.Schema, Raw: tftypes.NewValue(sch.Schema.Type().TerraformType(context.Background()), nil)}}
	r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan{Schema: sch.Schema, Raw: raw}}, resp)
	if !resp.Diagnostics.HasError() || len(api.creates) != 0 {
		t.Fatalf("expected a refusal with no request, diagnostics=%v requests=%d", resp.Diagnostics, len(api.creates))
	}
}

func TestReadAndImportReturnKindAndLists(t *testing.T) {
	api := &keyAPI{listRows: []any{map[string]any{
		"key_id": "key-1", "name": "gw", "prefix": "thoth_ab", "scope_level": "endpoint", "scope_target_id": "ep-1",
		"permissions": []any{"execute"}, "kind": "mcp_gateway",
		"allowed_agents": []any{"agent-a"}, "allowed_tools": []any{"metabase__*"},
		"created_at": "2026-11-26T00:00:00Z", "active": true, "needs_reissue": false,
	}}}
	r := keyResourceWithAPI(t, apiKeyScopeEndpoint, api)
	// Import starts from the id only.
	raw, sch := keyObject(t, r, map[string]tftypes.Value{"id": str("key-1"), "key_id": str("key-1"), "scope_level": str("endpoint")})
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: sch.Schema, Raw: raw}}
	r.Read(context.Background(), resource.ReadRequest{State: resp.State}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	var state endpointAPIKeyModel
	if d := resp.State.Get(context.Background(), &state); d.HasError() {
		t.Fatal(d)
	}
	if state.Kind.ValueString() != "mcp_gateway" ||
		!reflect.DeepEqual(setStrings(state.AllowedAgents), []string{"agent-a"}) ||
		!reflect.DeepEqual(setStrings(state.AllowedTools), []string{"metabase__*"}) {
		t.Fatalf("scope not read back: %+v", state)
	}
}

func TestReadOfAnOrdinaryKeyLeavesTheGatewayFieldsNull(t *testing.T) {
	g := flattenGatewayScope(map[string]any{"key_id": "k"}, nullGatewayScope())
	if !g.Kind.IsNull() || !g.AllowedAgents.IsNull() || !g.AllowedTools.IsNull() {
		t.Fatalf("expected nulls, got %+v", g)
	}
}

func TestReadShowsServerListWhenItDiffersFromState(t *testing.T) {
	prior := nullGatewayScope()
	prior.AllowedAgents = stringSetValue([]string{"agent-a"})
	g := flattenGatewayScope(map[string]any{"kind": "mcp_gateway", "allowed_agents": []any{"agent-a", "agent-b"}}, prior)
	if got := setStrings(g.AllowedAgents); len(got) != 2 {
		t.Fatalf("drift must show the server list, got %v", got)
	}
}

func TestReadKeepsTheConfiguredSpellingWhenTheServerListIsItsNormalForm(t *testing.T) {
	prior := nullGatewayScope()
	prior.AllowedAgents = stringSetValue([]string{"Agent-B", "agent-a", "AGENT-A"})
	prior.AllowedTools = stringSetValue([]string{"Metabase__Run"})
	g := flattenGatewayScope(map[string]any{
		"kind": "mcp_gateway", "allowed_agents": []any{"agent-a", "agent-b"}, "allowed_tools": []any{"metabase__run"},
	}, prior)
	if !g.AllowedAgents.Equal(prior.AllowedAgents) || !g.AllowedTools.Equal(prior.AllowedTools) {
		t.Fatalf("configured spelling was replaced, so the next plan would show a difference: %+v", g)
	}
}

func TestKeySecretStaysSensitiveWriteOnce(t *testing.T) {
	a := keySchema(t, keyResource(apiKeyScopeEndpoint)).Schema.Attributes["api_key"]
	if !a.IsSensitive() || !a.IsComputed() {
		t.Fatal("api_key must stay sensitive and computed")
	}
}
