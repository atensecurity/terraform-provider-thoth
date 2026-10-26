package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

// orgSecurityAPI stands in for GovAPI's /:tenant-id/settings/security.
type orgSecurityAPI struct {
	mu      sync.Mutex
	saved   map[string]any
	deletes int
	refuse  string // an error code to return on PUT
}

func (a *orgSecurityAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant-a/settings/security" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			if a.refuse != "" {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": a.refuse, "message": "refused"})
				return
			}
			body := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			body["updated_at"], body["updated_by"] = "2026-10-26T12:00:00Z", "api-key:key_1"
			a.saved = body
		case http.MethodDelete:
			a.deletes++
			a.saved = nil
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if a.saved == nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"require_mfa": false, "session_timeout_minutes": 720, "ip_allowlist": []any{}, "configured": false})
			return
		}
		out := map[string]any{"configured": true}
		for k, v := range a.saved {
			out[k] = v
		}
		_ = json.NewEncoder(w).Encode(out)
	})
}

func newOrgSecurityResource(t *testing.T, api *orgSecurityAPI) *orgSecuritySettingsResource {
	t.Helper()
	server := httptest.NewServer(api.handler(t))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	return &orgSecuritySettingsResource{client: c, tenantID: "tenant-a"}
}

func orgSecurityPlan(t *testing.T, mfa bool, minutes int64, ranges ...string) orgSecuritySettingsModel {
	t.Helper()
	values := make([]attr.Value, 0, len(ranges))
	for _, r := range ranges {
		values = append(values, types.StringValue(r))
	}
	return orgSecuritySettingsModel{
		RequireMFA:            types.BoolValue(mfa),
		SessionTimeoutMinutes: types.Int64Value(minutes),
		IPAllowlist:           types.SetValueMust(types.StringType, values),
	}
}

func TestOrgSecuritySettingsApplySavesTheWholePolicy(t *testing.T) {
	api := &orgSecurityAPI{}
	r := newOrgSecurityResource(t, api)
	var diags diag.Diagnostics
	next, ok := r.apply(context.Background(), orgSecurityPlan(t, true, 60, "203.0.113.0/24", "198.51.100.7/32"), &diags)
	if !ok || diags.HasError() {
		t.Fatalf("apply failed: %v", diags)
	}
	if api.saved["require_mfa"] != true || api.saved["session_timeout_minutes"] != float64(60) {
		t.Fatalf("saved %v", api.saved)
	}
	if got := api.saved["ip_allowlist"].([]any); len(got) != 2 {
		t.Fatalf("ip_allowlist sent %v", got)
	}
	if !next.RequireMFA.ValueBool() || next.SessionTimeoutMinutes.ValueInt64() != 60 || len(next.IPAllowlist.Elements()) != 2 {
		t.Fatalf("state %+v", next)
	}
	if next.UpdatedBy.ValueString() != "api-key:key_1" || next.ID.ValueString() != "tenant-a" {
		t.Fatalf("state %+v", next)
	}

	// An empty allowlist is sent as an empty list, never omitted.
	if _, ok := r.apply(context.Background(), orgSecurityPlan(t, false, 720), &diags); !ok {
		t.Fatalf("apply failed: %v", diags)
	}
	if got, present := api.saved["ip_allowlist"].([]any); !present || len(got) != 0 {
		t.Fatalf("ip_allowlist sent %v", api.saved["ip_allowlist"])
	}
}

func TestOrgSecuritySettingsExplainsGovAPIRefusals(t *testing.T) {
	api := &orgSecurityAPI{refuse: "ip_allowlist_excludes_caller"}
	r := newOrgSecurityResource(t, api)
	var diags diag.Diagnostics
	if _, ok := r.apply(context.Background(), orgSecurityPlan(t, false, 720, "198.51.100.0/24"), &diags); ok {
		t.Fatal("apply should fail")
	}
	if !strings.Contains(diags.Errors()[0].Detail(), "connects from") {
		t.Fatalf("detail %q", diags.Errors()[0].Detail())
	}
}

func TestOrgSecuritySettingsDeleteRemovesThePolicy(t *testing.T) {
	api := &orgSecurityAPI{saved: map[string]any{"require_mfa": true, "session_timeout_minutes": 60, "ip_allowlist": []any{}}}
	r := newOrgSecurityResource(t, api)
	out, err := r.client.GetOrgSecuritySettings(context.Background())
	if err != nil || out["configured"] != true {
		t.Fatalf("read %v %v", out, err)
	}
	if err := r.client.DeleteOrgSecuritySettings(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.deletes != 1 {
		t.Fatalf("deletes = %d", api.deletes)
	}
	out, err = r.client.GetOrgSecuritySettings(context.Background())
	if err != nil || out["configured"] != false {
		t.Fatalf("after delete %v %v", out, err)
	}
}

func TestCanonicalCIDRValidator(t *testing.T) {
	cases := map[string]bool{
		"203.0.113.7/32":  true,
		"198.51.100.0/24": true,
		"2001:db8::/32":   true,
		"203.0.113.7":     false, // bare address: write /32
		"198.51.100.9/24": false, // host bits set: write .0/24
		"10.0.0.0/33":     false,
		"example.com":     false,
	}
	for value, valid := range cases {
		resp := &validator.StringResponse{}
		canonicalCIDRValidator{}.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("ip_allowlist"), ConfigValue: types.StringValue(value)}, resp)
		if resp.Diagnostics.HasError() == valid {
			t.Errorf("%s: valid=%v, diagnostics %v", value, valid, resp.Diagnostics)
		}
	}
	resp := &validator.StringResponse{}
	canonicalCIDRValidator{}.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("ip_allowlist"), ConfigValue: types.StringValue("203.0.113.7")}, resp)
	if !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), `"203.0.113.7/32"`) {
		t.Fatalf("the error names the canonical form: %v", resp.Diagnostics)
	}
}
