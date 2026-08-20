package resources

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

func TestFlattenMCPVendor_OptionalComputedDefaultsToKnownNull(t *testing.T) {
	current := mcpVendorModel{
		ManifestSignatureStatus: types.StringUnknown(),
		ManifestSignatureSigner: types.StringUnknown(),
		ManifestSignatureBundle: types.StringUnknown(),
		ManifestSignatureAt:     types.StringUnknown(),
		Capabilities:            types.ListUnknown(types.StringType),
		RuntimeIdentity:         types.StringUnknown(),
		EgressPolicyMode:        types.StringUnknown(),
		EgressAllowedHosts:      types.ListUnknown(types.StringType),
		Source:                  types.StringUnknown(),
		Notes:                   types.StringUnknown(),
		LastSeenAt:              types.StringUnknown(),
		CreatedAt:               types.StringUnknown(),
		UpdatedAt:               types.StringUnknown(),
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

	if next.Source.IsUnknown() ||
		next.Notes.IsUnknown() ||
		next.LastSeenAt.IsUnknown() ||
		next.ManifestSignatureStatus.IsUnknown() ||
		next.RuntimeIdentity.IsUnknown() ||
		next.Capabilities.IsUnknown() ||
		next.EgressPolicyMode.IsUnknown() ||
		next.EgressAllowedHosts.IsUnknown() {
		t.Fatalf("optional+computed fields must be known after flatten")
	}
	if !next.Source.IsNull() ||
		!next.Notes.IsNull() ||
		!next.LastSeenAt.IsNull() ||
		!next.ManifestSignatureStatus.IsNull() ||
		!next.RuntimeIdentity.IsNull() ||
		!next.Capabilities.IsNull() ||
		!next.EgressPolicyMode.IsNull() ||
		!next.EgressAllowedHosts.IsNull() {
		t.Fatalf("expected omitted optional fields to settle to null")
	}
}

func TestFlattenMCPVendor_IncludesManifestCapabilityAndEgressFields(t *testing.T) {
	next := flattenMCPVendor(
		context.Background(),
		map[string]any{
			"vendor_id":        "openai",
			"display_name":     "OpenAI",
			"approved":         true,
			"host_patterns":    []any{"api.openai.com"},
			"runtime_identity": "mcp_runtime:openai",
			"capabilities":     []any{"mcp.search", "mcp.fetch"},
			"manifest_signature": map[string]any{
				"status":      "verified",
				"signer":      "security@atensecurity.com",
				"bundle_ref":  "rekor://entry/abc123",
				"verified_at": "2026-08-19T12:00:00Z",
			},
			"egress_policy": map[string]any{
				"mode":                  "enforce",
				"allowed_host_patterns": []any{"api.openai.com", "*.openai.com"},
			},
		},
		mcpVendorModel{},
		"trantor",
	)

	if next.ManifestSignatureStatus.ValueString() != "verified" {
		t.Fatalf("manifest_signature_status = %q, want verified", next.ManifestSignatureStatus.ValueString())
	}
	if next.ManifestSignatureSigner.ValueString() != "security@atensecurity.com" {
		t.Fatalf("manifest_signature_signer = %q", next.ManifestSignatureSigner.ValueString())
	}
	if next.ManifestSignatureBundle.ValueString() != "rekor://entry/abc123" {
		t.Fatalf("manifest_signature_bundle_ref = %q", next.ManifestSignatureBundle.ValueString())
	}
	if next.ManifestSignatureAt.ValueString() != "2026-08-19T12:00:00Z" {
		t.Fatalf("manifest_signature_verified_at = %q", next.ManifestSignatureAt.ValueString())
	}
	if next.RuntimeIdentity.ValueString() != "mcp_runtime:openai" {
		t.Fatalf("runtime_identity = %q", next.RuntimeIdentity.ValueString())
	}
	if next.EgressPolicyMode.ValueString() != "enforce" {
		t.Fatalf("egress_policy_mode = %q", next.EgressPolicyMode.ValueString())
	}

	var capabilities []string
	if diags := next.Capabilities.ElementsAs(context.Background(), &capabilities, false); diags.HasError() {
		t.Fatalf("ElementsAs(capabilities) returned diagnostics: %v", diags)
	}
	if len(capabilities) != 2 {
		t.Fatalf("capabilities = %v, want 2 values", capabilities)
	}

	var egressHosts []string
	if diags := next.EgressAllowedHosts.ElementsAs(context.Background(), &egressHosts, false); diags.HasError() {
		t.Fatalf("ElementsAs(egress_allowed_host_patterns) returned diagnostics: %v", diags)
	}
	if len(egressHosts) != 2 {
		t.Fatalf("egress_allowed_host_patterns = %v, want 2 values", egressHosts)
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
