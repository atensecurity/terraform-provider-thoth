package resources

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

// The monorepo's docs/product/parity scenarios record the request each path
// sends for one change; GovAPI replays them and asserts the same stored state.
// These tests keep the provider's side of that contract. The scenarios are not
// published with the provider, so the tests skip outside the monorepo.

type parityRequest struct {
	Method string         `json:"method"`
	Path   string         `json:"path"`
	Body   map[string]any `json:"body"`
}

func loadParityTerraform(t *testing.T, name string) parityRequest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "docs", "product", "parity", name+".json"))
	if os.IsNotExist(err) {
		t.Skip("parity scenarios live in the monorepo")
	}
	if err != nil {
		t.Fatal(err)
	}
	var scenario struct {
		Terraform parityRequest `json:"terraform"`
	}
	if err := json.Unmarshal(raw, &scenario); err != nil {
		t.Fatal(err)
	}
	return scenario.Terraform
}

// captureRequest returns a client whose requests are recorded.
func captureRequest(t *testing.T) (*client.Client, *parityRequest) {
	t.Helper()
	got := &parityRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Method, got.Path = r.Method, r.URL.Path
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &got.Body)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	return c, got
}

func assertParity(t *testing.T, want parityRequest, got *parityRequest) {
	t.Helper()
	if got.Method != want.Method || !strings.HasSuffix(got.Path, "/tenant-a/"+want.Path) {
		t.Fatalf("request %s %s, want %s .../tenant-a/%s", got.Method, got.Path, want.Method, want.Path)
	}
	wantJSON, _ := json.Marshal(want.Body)
	gotJSON, _ := json.Marshal(got.Body)
	if string(wantJSON) != string(gotJSON) {
		t.Fatalf("body %s, want %s", gotJSON, wantJSON)
	}
}

func TestParityAgentEnforcementMode(t *testing.T) {
	want := loadParityTerraform(t, "agent_enforcement_mode")
	c, got := captureRequest(t)
	if _, err := c.UpdateAgentEnforcement(context.Background(), "agent-a", "enforce", "deny"); err != nil {
		t.Fatal(err)
	}
	assertParity(t, want, got)
}

func TestParityDataHandling(t *testing.T) {
	want := loadParityTerraform(t, "data_handling")
	c, got := captureRequest(t)
	if _, err := c.UpdateDataHandling(context.Background(), "redact", "hash"); err != nil {
		t.Fatal(err)
	}
	assertParity(t, want, got)
}

func TestParitySIEMDecisionStream(t *testing.T) {
	want := loadParityTerraform(t, "siem_decision_stream")
	c, got := captureRequest(t)
	if _, err := c.UpdateSIEMDecisionStream(context.Background(), false, "all", 0.25); err != nil {
		t.Fatal(err)
	}
	assertParity(t, want, got)
}

func TestParityToolDeclaration(t *testing.T) {
	str := func(v string) types.String {
		if v == "" {
			return types.StringNull()
		}
		return types.StringValue(v)
	}
	for _, tc := range []struct {
		scenario, tool, class, agent, sensitivity, privilege string
	}{
		{"tool_declaration", "orders.list", "read", "", "", ""},
		{"tool_declaration_agent_context", "payments.refund", "write", "agent-a", "restricted", "elevated"},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			want := loadParityTerraform(t, tc.scenario)
			ctx := context.Background()
			classes, diags := types.SetValueFrom(ctx, types.StringType, []string{tc.class})
			if diags.HasError() {
				t.Fatal(diags)
			}
			model := toolClassificationModel{ToolName: types.StringValue(tc.tool), Classes: classes, AgentID: str(tc.agent), TargetSensitivity: str(tc.sensitivity), ActingPrivilege: str(tc.privilege)}
			body, err := toolClassificationBody(ctx, &model, nil)
			if err != nil {
				t.Fatal(err)
			}
			c, got := captureRequest(t)
			// A resource create posts the declaration.
			if _, err := c.ToolClassification(ctx, http.MethodPost, "", body); err != nil {
				t.Fatal(err)
			}
			assertParity(t, want, got)
		})
	}
}

func TestParityOrgSecuritySettings(t *testing.T) {
	want := loadParityTerraform(t, "org_security_settings")
	c, got := captureRequest(t)
	r := &orgSecuritySettingsResource{client: c, tenantID: "tenant-a"}
	var diags diag.Diagnostics
	plan := orgSecuritySettingsModel{
		RequireMFA:            types.BoolValue(true),
		SessionTimeoutMinutes: types.Int64Value(240),
		IPAllowlist:           types.SetValueMust(types.StringType, []attr.Value{types.StringValue("192.0.2.0/24"), types.StringValue("203.0.113.7/32")}),
	}
	r.apply(context.Background(), plan, &diags)
	assertParity(t, want, got)
}
