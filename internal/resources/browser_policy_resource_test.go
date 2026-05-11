package resources

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestFlattenBrowserPolicy_OptionalComputedDefaultsToKnownNull(t *testing.T) {
	current := browserPolicyModel{
		Version:   types.Int64Unknown(),
		CreatedBy: types.StringUnknown(),
		UpdatedBy: types.StringUnknown(),
	}

	next := flattenBrowserPolicy(
		map[string]any{
			"policy_id": "chrome-guardrails",
			"name":      "Chrome Guardrails",
			"provider":  "chrome",
			"active":    true,
		},
		current,
		"trantor",
	)

	if next.Version.IsUnknown() || next.CreatedBy.IsUnknown() || next.UpdatedBy.IsUnknown() {
		t.Fatalf("optional+computed fields must be known after apply")
	}
	if !next.Version.IsNull() || !next.CreatedBy.IsNull() || !next.UpdatedBy.IsNull() {
		t.Fatalf("expected omitted fields to settle to null values")
	}
}

func TestFlattenBrowserPolicy_PreservesConfiguredOverridesWhenAPIOmitsFields(t *testing.T) {
	current := browserPolicyModel{
		Version:   types.Int64Value(7),
		CreatedBy: types.StringValue("terraform"),
		UpdatedBy: types.StringValue("terraform"),
	}

	next := flattenBrowserPolicy(
		map[string]any{
			"policy_id": "chrome-guardrails",
			"name":      "Chrome Guardrails",
			"provider":  "chrome",
			"active":    true,
		},
		current,
		"trantor",
	)

	if next.Version.ValueInt64() != 7 {
		t.Fatalf("expected version override to be preserved, got %d", next.Version.ValueInt64())
	}
	if next.CreatedBy.ValueString() != "terraform" {
		t.Fatalf("expected created_by override to be preserved, got %q", next.CreatedBy.ValueString())
	}
	if next.UpdatedBy.ValueString() != "terraform" {
		t.Fatalf("expected updated_by override to be preserved, got %q", next.UpdatedBy.ValueString())
	}
}
