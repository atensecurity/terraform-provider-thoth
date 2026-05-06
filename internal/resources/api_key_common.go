package resources

import (
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

const (
	apiKeyScopeFleet    = "fleet"
	apiKeyScopeEndpoint = "endpoint"
	apiKeyScopeAgent    = "agent"
)

type apiKeyModel struct {
	ID            types.String `tfsdk:"id"`
	TenantID      types.String `tfsdk:"tenant_id"`
	KeyID         types.String `tfsdk:"key_id"`
	Name          types.String `tfsdk:"name"`
	ScopeLevel    types.String `tfsdk:"scope_level"`
	ScopeTargetID types.String `tfsdk:"scope_target_id"`
	Permissions   types.List   `tfsdk:"permissions"`
	TTLSeconds    types.Int64  `tfsdk:"ttl_seconds"`
	JITReason     types.String `tfsdk:"jit_reason"`
	APIKey        types.String `tfsdk:"api_key"`
	Prefix        types.String `tfsdk:"prefix"`
	CreatedAt     types.String `tfsdk:"created_at"`
	ExpiresAt     types.String `tfsdk:"expires_at"`
	LastUsedAt    types.String `tfsdk:"last_used_at"`
	Active        types.Bool   `tfsdk:"active"`
}

func flattenAPIKeyCreated(row map[string]any, plan apiKeyModel, tenantID string) apiKeyModel {
	next := plan
	keyID := tfhelpers.GetString(row, "key_id")
	next.ID = types.StringValue(keyID)
	next.KeyID = types.StringValue(keyID)
	next.TenantID = types.StringValue(tenantID)
	if v := tfhelpers.GetString(row, "name"); v != "" {
		next.Name = types.StringValue(v)
	}
	next.APIKey = nullableString(row, "api_key")
	next.Prefix = nullableString(row, "prefix")
	next.CreatedAt = nullableString(row, "created_at")
	next.ExpiresAt = nullableString(row, "expires_at")
	next.Active = types.BoolValue(true)
	next.LastUsedAt = types.StringNull()
	return next
}

func flattenAPIKeyInfo(row map[string]any, state apiKeyModel, tenantID string) apiKeyModel {
	next := state
	keyID := tfhelpers.GetString(row, "key_id")
	next.ID = types.StringValue(keyID)
	next.KeyID = types.StringValue(keyID)
	next.TenantID = types.StringValue(tenantID)
	next.Name = nullableString(row, "name")
	next.Prefix = nullableString(row, "prefix")
	next.ScopeLevel = nullableString(row, "scope_level")
	next.ScopeTargetID = nullableString(row, "scope_target_id")
	perms := tfhelpers.GetStringSlice(row, "permissions")
	next.Permissions = tfhelpers.StringSliceValue(perms)
	next.CreatedAt = nullableString(row, "created_at")
	next.ExpiresAt = nullableString(row, "expires_at")
	next.LastUsedAt = nullableString(row, "last_used_at")
	next.Active = types.BoolValue(tfhelpers.GetBool(row, "active"))
	return next
}
