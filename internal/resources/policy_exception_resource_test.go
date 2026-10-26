package resources

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// The API never returns the hold token, so a read keeps the configured value
// instead of planning a replacement.
func TestFlattenPolicyExceptionKeepsTheConfiguredHoldToken(t *testing.T) {
	current := policyExceptionResourceModel{HoldToken: types.StringValue("hold-1")}
	next := flattenPolicyException(current, map[string]any{"request_id": "per_1", "status": "pending"}, "tenant-a")
	if next.HoldToken.ValueString() != "hold-1" {
		t.Fatalf("hold_token = %q, want the configured value", next.HoldToken.ValueString())
	}
	unset := flattenPolicyException(policyExceptionResourceModel{HoldToken: types.StringNull()}, map[string]any{"request_id": "per_2"}, "tenant-a")
	if !unset.HoldToken.IsNull() {
		t.Fatalf("hold_token = %q, want null when not configured", unset.HoldToken.ValueString())
	}
}
