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

func TestParityToolDeclaration(t *testing.T) {
	want := loadParityTerraform(t, "tool_declaration")
	ctx := context.Background()
	classes, diags := types.SetValueFrom(ctx, types.StringType, []string{"read"})
	if diags.HasError() {
		t.Fatal(diags)
	}
	model := toolClassificationModel{ToolName: types.StringValue("orders.list"), Classes: classes, AgentID: types.StringNull(), TargetSensitivity: types.StringNull(), ActingPrivilege: types.StringNull()}
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
}
