package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// brokerServer stands in for govapi's settings route: it stores what is PUT
// and normalizes the secret broker the way govapi does (lower-cased hosts,
// sorted and de-duplicated agent_ids and tools, no leading space on a prefix),
// so a round trip shows what an apply would really see.
func brokerServer(t *testing.T, stored map[string]any) (*governanceSettingsResource, *[]map[string]any) {
	t.Helper()
	writes := []map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.URL.Path == "/test/thoth/compliance/catalogue" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if req.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(stored)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		writes = append(writes, payload)
		if broker, ok := payload["secret_broker"].(map[string]any); ok {
			bindings, _ := broker["auth_bindings"].([]any)
			for _, raw := range bindings {
				b := raw.(map[string]any)
				b["host_pattern"] = strings.ToLower(b["host_pattern"].(string))
				if prefix, ok := b["prefix"].(string); ok {
					b["prefix"] = strings.TrimLeft(prefix, " \t")
				}
				for _, key := range []string{"agent_ids", "tools"} {
					if list, ok := b[key].([]any); ok {
						names := []string{}
						for _, item := range list {
							names = append(names, strings.ToLower(strings.TrimSpace(item.(string))))
						}
						b[key] = sortedUnique(names)
					}
				}
			}
		}
		stored = payload
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "test", APIKey: "fixture", RetryMaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	return &governanceSettingsResource{client: c, tenantID: "test"}, &writes
}

func sortedUnique(in []string) []any {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	res := make([]any, len(out))
	for i, v := range out {
		res[i] = v
	}
	return res
}

const scopedBindingsJSON = `[{"id":"crm","host_pattern":"API.example.com","header":"Authorization","secret_ref":"aws-sm://t/secret-broker/crm","prefix":"Bearer ","agent_ids":["Bot-B","bot-a","bot-a"],"tools":["crm.read"]}]`

// An apply carries a binding's id, agent_ids and tools to the server, keeps
// every field of the stored document it does not model, leaves fail_on_missing_secret
// out when it is not configured, and reports no drift for the server's own
// normalization of what was configured.
func TestGovernanceSecretBrokerRoundTripKeepsScopeFieldsAndUnmodelledFields(t *testing.T) {
	stored := map[string]any{
		"webhook":     map[string]any{"secret": "__unchanged__", "url": "https://hooks.example.com/x"},
		"future_flag": true,
		"secret_broker": map[string]any{
			"enabled": true, "provider": "aws_secrets_manager",
			"a_field_this_resource_does_not_model": "keep me",
		},
	}
	r, writes := brokerServer(t, stored)
	plan := governanceSettingsModel{
		SecretBrokerAuthBindingsJSON: types.StringValue(scopedBindingsJSON),
		SecretBrokerAllowedHosts:     types.ListValueMust(types.StringType, nil),
	}
	plan.SecretBrokerAllowedHosts = types.ListNull(types.StringType)
	var d diag.Diagnostics
	state, ok := r.apply(context.Background(), plan, governanceSettingsModel{}, &d)
	if !ok || d.HasError() {
		t.Fatal(d)
	}
	if len(*writes) != 1 {
		t.Fatalf("writes: %v", *writes)
	}
	put := (*writes)[0]
	broker := put["secret_broker"].(map[string]any)
	if broker["a_field_this_resource_does_not_model"] != "keep me" || put["future_flag"] != true {
		t.Fatalf("an apply dropped a field it does not model: %v", put)
	}
	if put["webhook"].(map[string]any)["secret"] != "__unchanged__" {
		t.Fatalf("an apply touched the webhook secret: %v", put["webhook"])
	}
	if _, present := broker["fail_on_missing_secret"]; present {
		t.Fatalf("an unconfigured fail_on_missing_secret was sent: %v", broker)
	}
	binding := broker["auth_bindings"].([]any)[0].(map[string]any)
	if binding["id"] != "crm" || len(binding["agent_ids"].([]any)) != 2 || binding["tools"].([]any)[0] != "crm.read" {
		t.Fatalf("scope fields did not reach the server: %v", binding)
	}
	if binding["prefix"] != "Bearer " {
		t.Fatalf("the prefix lost its trailing space: %q", binding["prefix"])
	}
	// The server lower-cased the host and sorted the agents; the configured text
	// still stands, so Terraform sees no inconsistent result and no drift.
	if state.SecretBrokerAuthBindingsJSON.ValueString() != scopedBindingsJSON {
		t.Fatalf("state differs from the configuration: %s", state.SecretBrokerAuthBindingsJSON.ValueString())
	}
	// A refresh with the same stored document is also stable.
	refreshed := flattenGovernanceSettings(put, state, "test")
	if refreshed.SecretBrokerAuthBindingsJSON.ValueString() != scopedBindingsJSON {
		t.Fatalf("refresh reported drift: %s", refreshed.SecretBrokerAuthBindingsJSON.ValueString())
	}
	// A binding that really changed on the server is reported.
	changed := map[string]any{"secret_broker": map[string]any{"auth_bindings": []any{map[string]any{"host_pattern": "other.example.com", "header": "X", "secret_ref": "aws-sm://t/secret-broker/x", "prefix": ""}}}}
	drifted := flattenGovernanceSettings(changed, state, "test")
	if !strings.Contains(drifted.SecretBrokerAuthBindingsJSON.ValueString(), "other.example.com") {
		t.Fatal("real drift was hidden")
	}
}

func TestNormalizeBindingsJSONMatchesTheServer(t *testing.T) {
	a := normalizeBindingsJSON(`[{"host_pattern":" API.Example.com ","header":"H","secret_ref":"r","prefix":" Bearer ","agent_ids":["B","a","a",""],"tools":[],"id":" "}]`)
	b := normalizeBindingsJSON(`[{"agent_ids":["a","b"],"header":"H","host_pattern":"api.example.com","prefix":"Bearer ","secret_ref":"r"}]`)
	if a != b {
		t.Fatalf("%s != %s", a, b)
	}
	if normalizeBindingsJSON(`[{"host_pattern":"a","header":"H","secret_ref":"r","prefix":"Bearer"}]`) == normalizeBindingsJSON(`[{"host_pattern":"a","header":"H","secret_ref":"r","prefix":"Bearer "}]`) {
		t.Fatal("a prefix with and without its trailing space are different bindings")
	}
	// The server trims upstream; an empty one is the same as none.
	if normalizeBindingsJSON(`[{"host_pattern":"a.b","header":"H","secret_ref":"r","prefix":"","upstream":" metabase "}]`) !=
		normalizeBindingsJSON(`[{"host_pattern":"a.b","header":"H","secret_ref":"r","prefix":"","upstream":"metabase"}]`) ||
		normalizeBindingsJSON(`[{"host_pattern":"a.b","header":"H","secret_ref":"r","prefix":"","upstream":" "}]`) !=
			normalizeBindingsJSON(`[{"host_pattern":"a.b","header":"H","secret_ref":"r","prefix":""}]`) {
		t.Fatal("upstream is trimmed and empty means none")
	}
	if got := normalizeBindingsJSON("not json"); got != "not json" {
		t.Fatal(got)
	}
}

func TestGovernanceSecretBrokerFailOnMissingIsSentOnlyWhenConfigured(t *testing.T) {
	for _, tc := range []struct {
		name   string
		model  types.Bool
		wantIn bool
	}{{"unset", types.BoolNull(), false}, {"explicit false", types.BoolValue(false), true}, {"true", types.BoolValue(true), true}} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{"secret_broker": map[string]any{}}
			var d diag.Diagnostics
			applyGovernanceSettingsPlan(&payload, governanceSettingsModel{SecretBrokerFailOnMissing: tc.model}, &d)
			_, present := payload["secret_broker"].(map[string]any)["fail_on_missing_secret"]
			if present != tc.wantIn {
				t.Fatalf("present=%v want %v: %v", present, tc.wantIn, payload)
			}
		})
	}
}
