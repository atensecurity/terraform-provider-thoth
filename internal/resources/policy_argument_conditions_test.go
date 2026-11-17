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
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

func conditionList(t *testing.T, items ...map[string]attr.Value) types.List {
	t.Helper()
	values := make([]attr.Value, 0, len(items))
	for _, item := range items {
		values = append(values, types.ObjectValueMust(argumentConditionAttrTypes, item))
	}
	return types.ListValueMust(types.ObjectType{AttrTypes: argumentConditionAttrTypes}, values)
}

func amountOver100(whenMissing string) map[string]attr.Value {
	missing := types.StringNull()
	if whenMissing != "" {
		missing = types.StringValue(whenMissing)
	}
	return map[string]attr.Value{
		"argument": types.StringValue("amount"), "operator": types.StringValue("gt"),
		"value": types.Float64Value(100), "when_missing": missing,
	}
}

func planWithConditions(t *testing.T, rulesJSON string, items ...map[string]attr.Value) policyResourceModel {
	plan := policyPlan(rulesJSON)
	plan.ArgumentConditions = types.ListNull(types.ObjectType{AttrTypes: argumentConditionAttrTypes})
	if len(items) > 0 {
		plan.ArgumentConditions = conditionList(t, items...)
	}
	return plan
}

func TestPolicyPayloadCarriesArgumentConditionsInsideRules(t *testing.T) {
	plan := planWithConditions(t, `{"tool":"approve_expense"}`, amountOver100(""), map[string]attr.Value{
		"argument": types.StringValue("expense.items"), "operator": types.StringValue("lte"),
		"value": types.Float64Value(2.5), "when_missing": types.StringValue("match"),
	})
	payload, err := policyPayload(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(payload["rules"])
	want := `{"argument_conditions":[{"argument":"amount","operator":"gt","value":100},{"argument":"expense.items","operator":"lte","value":2.5,"when_missing":"match"}],"tool":"approve_expense"}`
	if string(data) != want {
		t.Fatalf("rules %s", data)
	}
}

func TestPolicyPayloadRefusesConditionsInBothPlaces(t *testing.T) {
	plan := planWithConditions(t, `{"tool":"a","argument_conditions":[{"argument":"x","operator":"gt","value":1}]}`, amountOver100(""))
	if _, err := policyPayload(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "one place") {
		t.Fatalf("error %v", err)
	}
	// Conditions written under rules_json alone pass straight through.
	rulesOnly := planWithConditions(t, `{"tool":"a","argument_conditions":[{"argument":"x","operator":"gt","value":1}]}`)
	payload, err := policyPayload(context.Background(), rulesOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["rules"].(map[string]any)["argument_conditions"]; !ok {
		t.Fatalf("rules %v", payload["rules"])
	}
}

func TestFlattenReadsConditionsBackIntoTheTypedBlockWithoutDrift(t *testing.T) {
	configured := `{ "tool": "approve_expense" }`
	row := map[string]any{
		"id": "abc", "environment": "prod", "name": "Hold deletes", "type": "scope", "enforcement": "review", "status": "active",
		"applied_to": []any{"agent-a"},
		"rules": map[string]any{
			"tool":                "approve_expense",
			"argument_conditions": []any{map[string]any{"argument": "amount", "operator": "gt", "value": float64(100)}},
		},
	}
	plan := planWithConditions(t, configured, amountOver100(""))
	next, diags := flattenPolicy(context.Background(), row, plan, "tenant-a")
	if diags.HasError() {
		t.Fatal(diags)
	}
	if next.RulesJSON.ValueString() != configured {
		t.Fatalf("rules_json showed drift: %s", next.RulesJSON.ValueString())
	}
	if !next.ArgumentConditions.Equal(plan.ArgumentConditions) {
		t.Fatalf("conditions %v", next.ArgumentConditions)
	}

	// A change made elsewhere shows as drift in the block.
	row["rules"].(map[string]any)["argument_conditions"] = []any{map[string]any{"argument": "amount", "operator": "gt", "value": float64(500), "when_missing": "match"}}
	next, _ = flattenPolicy(context.Background(), row, plan, "tenant-a")
	if next.ArgumentConditions.Equal(plan.ArgumentConditions) {
		t.Fatal("a changed threshold must show as drift")
	}
	// A removal elsewhere shows as the block going null.
	delete(row["rules"].(map[string]any), "argument_conditions")
	next, _ = flattenPolicy(context.Background(), row, plan, "tenant-a")
	if !next.ArgumentConditions.IsNull() {
		t.Fatalf("conditions %v", next.ArgumentConditions)
	}
}

func TestFlattenLeavesConditionsInRulesJSONWhenThatIsWhereTheyWereConfigured(t *testing.T) {
	configured := `{"tool":"a","argument_conditions":[{"argument":"x","operator":"gt","value":1}]}`
	row := map[string]any{
		"id": "abc", "environment": "prod", "name": "n", "type": "scope", "enforcement": "review", "status": "active",
		"rules": map[string]any{"tool": "a", "argument_conditions": []any{map[string]any{"argument": "x", "operator": "gt", "value": float64(1)}}},
	}
	next, diags := flattenPolicy(context.Background(), row, planWithConditions(t, configured), "tenant-a")
	if diags.HasError() {
		t.Fatal(diags)
	}
	if next.RulesJSON.ValueString() != configured || !next.ArgumentConditions.IsNull() {
		t.Fatalf("state %+v", next)
	}
}

func TestArgumentPathPatternMatchesTheServer(t *testing.T) {
	for path, ok := range map[string]bool{
		"amount": true, "expense.amount": true, "a.b.c.d": true, "a-b_c9": true,
		"": false, "$where": false, "a.$b": false, "a..b": false, ".a": false, "a.": false, "a b": false,
		"1a": false, "_a": false, "a.b.c.d.e": false, "a[0]": false, strings.Repeat("x", 65): false,
	} {
		if argumentPathPattern.MatchString(path) != ok {
			t.Errorf("%q: want %v", path, ok)
		}
	}
}

// The monorepo's parity scenario for this change (docs/product/parity): the
// create the resource sends, with the query the route needs.
func TestParityPolicyRuleArgumentConditions(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "docs", "product", "parity", "policy_rule_argument_conditions.json"))
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
	plan := planWithConditions(t, `{"tool":"approve_expense"}`, amountOver100(""))
	plan.Name = types.StringValue("Hold large expenses")
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
