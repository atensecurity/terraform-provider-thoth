package resources

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

// The parity scenario for after_tools (docs/product/parity): rules_json passes it through unchanged.
func TestParityPolicyRuleAfterTools(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "docs", "product", "parity", "policy_rule_after_tools.json"))
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
	got := &parityRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Method, got.Path = r.Method, r.URL.Path+"?"+r.URL.RawQuery
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &got.Body)
		_, _ = w.Write([]byte(`{"id":"abc"}`))
	}))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	plan := planWithConditions(t, `{"tool_names":["git_push","send_email"],"after_tools":["metabase_*"]}`)
	plan.Name = types.StringValue("Hold publish after a query")
	plan.AppliedTo = types.ListValueMust(types.StringType, []attr.Value{types.StringValue("all")})
	payload, err := policyPayload(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	payload["environment"] = "prod"
	if _, err := c.CreatePolicy(context.Background(), "prod", payload); err != nil {
		t.Fatal(err)
	}
	assertParity(t, scenario.Terraform, got)
}
