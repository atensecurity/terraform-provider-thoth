package resources

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

func TestFlattenMCPVendor_OptionalComputedDefaultsToKnownNull(t *testing.T) {
	current := mcpVendorModel{
		Source:     types.StringUnknown(),
		Notes:      types.StringUnknown(),
		LastSeenAt: types.StringUnknown(),
		CreatedAt:  types.StringUnknown(),
		UpdatedAt:  types.StringUnknown(),
	}

	next := flattenMCPVendor(
		context.Background(),
		map[string]any{
			"vendor_id":     "openai",
			"display_name":  "OpenAI",
			"approved":      true,
			"host_patterns": []any{"api.openai.com"},
		},
		current,
		"trantor",
	)

	if next.Source.IsUnknown() || next.Notes.IsUnknown() || next.LastSeenAt.IsUnknown() {
		t.Fatalf("optional+computed fields must be known after flatten")
	}
	if !next.Source.IsNull() || !next.Notes.IsNull() || !next.LastSeenAt.IsNull() {
		t.Fatalf("expected omitted optional fields to settle to null")
	}
}

func TestFlattenMCPVendor_PreservesCurrentHostPatternOrderWhenSetMatches(t *testing.T) {
	current := mcpVendorModel{
		HostPatterns: tfhelpers.StringSliceValue([]string{"api.openai.com", "*.openai.com"}),
	}

	next := flattenMCPVendor(
		context.Background(),
		map[string]any{
			"vendor_id":     "openai",
			"display_name":  "OpenAI",
			"approved":      true,
			"host_patterns": []any{"*.openai.com", "api.openai.com"},
		},
		current,
		"trantor",
	)

	var hostPatterns []string
	if diags := next.HostPatterns.ElementsAs(context.Background(), &hostPatterns, false); diags.HasError() {
		t.Fatalf("ElementsAs(host_patterns) returned diagnostics: %v", diags)
	}

	if len(hostPatterns) != 2 || hostPatterns[0] != "api.openai.com" || hostPatterns[1] != "*.openai.com" {
		t.Fatalf("host_patterns = %v, want [api.openai.com *.openai.com]", hostPatterns)
	}
}

func TestParseMCPVendorImportID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "vendor only", in: "openai", want: "openai"},
		{name: "tenant and vendor", in: "example-tenant/openai", want: "openai"},
		{name: "trim spaces", in: "  example-tenant/openai  ", want: "openai"},
		{name: "empty", in: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMCPVendorImportID(tc.in)
			if got != tc.want {
				t.Fatalf("parseMCPVendorImportID(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
