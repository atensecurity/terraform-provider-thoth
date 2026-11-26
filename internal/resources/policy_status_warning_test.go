package resources

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// A pending rule is not enforced, and enabled stays true for it, so a plan
// shows no difference. The provider must say so when it reads one.

func TestPolicyStatusWarningNamesPendingAndRejectedRules(t *testing.T) {
	model := policyPlan("")
	model.ID = types.StringValue("prod/abc")

	model.Status = types.StringValue("pending")
	diags := policyStatusWarning(model)
	if len(diags) != 1 || diags[0].Severity() != diag.SeverityWarning {
		t.Fatalf("pending: %v", diags)
	}
	detail := diags[0].Detail()
	for _, want := range []string{"prod/abc", "not enforcing", "signed-in org admin", "thothctl governance policies decide", "no difference"} {
		if !strings.Contains(detail, want) {
			t.Errorf("warning %q lacks %q", detail, want)
		}
	}

	model.Status = types.StringValue("rejected")
	if diags := policyStatusWarning(model); len(diags) != 1 || diags[0].Severity() != diag.SeverityWarning {
		t.Fatalf("rejected: %v", diags)
	}
	for _, status := range []string{"active", "disabled", ""} {
		model.Status = types.StringValue(status)
		if diags := policyStatusWarning(model); len(diags) != 0 {
			t.Errorf("status %q must not warn: %v", status, diags)
		}
	}
}

func TestPolicyDescriptionsDoNotPromiseAdminKeyActivation(t *testing.T) {
	schemaResp := &resource.SchemaResponse{}
	(&policyResource{}).Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	for name, attr := range schemaResp.Schema.Attributes {
		if strings.Contains(attr.GetDescription(), "org admin's key") {
			t.Errorf("%s still says an org admin's key turns a rule on", name)
		}
	}
	if strings.Contains(schemaResp.Schema.Description, "not an org admin's") {
		t.Error("the resource description still says only a non-admin key starts pending")
	}
	if !strings.Contains(schemaResp.Schema.Description, "always waits for a person") {
		t.Error("the resource description must say a key's write always waits for a person")
	}
}
