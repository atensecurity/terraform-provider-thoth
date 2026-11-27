package resources

import (
	"sort"
	"strings"

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

// gatewayScopeFields are the attributes only thoth_endpoint_api_key has.
type gatewayScopeFields struct {
	Kind          types.String `tfsdk:"kind"`
	AllowedAgents types.Set    `tfsdk:"allowed_agents"`
	AllowedTools  types.Set    `tfsdk:"allowed_tools"`
}

// endpointAPIKeyModel is the state of thoth_endpoint_api_key.
type endpointAPIKeyModel struct {
	apiKeyModel
	gatewayScopeFields
}

func nullGatewayScope() gatewayScopeFields {
	return gatewayScopeFields{
		Kind:          types.StringNull(),
		AllowedAgents: types.SetNull(types.StringType),
		AllowedTools:  types.SetNull(types.StringType),
	}
}

func stringSetValue(values []string) types.Set {
	if len(values) == 0 {
		return types.SetNull(types.StringType)
	}
	items := make([]types.String, 0, len(values))
	for _, v := range values {
		items = append(items, types.StringValue(v))
	}
	set, _ := types.SetValueFrom(nil, types.StringType, items)
	return set
}

func setStrings(set types.Set) []string {
	if set.IsNull() || set.IsUnknown() {
		return nil
	}
	out := make([]string, 0, len(set.Elements()))
	for _, el := range set.Elements() {
		if s, ok := el.(types.String); ok && !s.IsNull() && !s.IsUnknown() {
			out = append(out, s.ValueString())
		}
	}
	return out
}

// flattenGatewayScope reads kind and the lists back from a key row. The
// server stores the lists lower-cased, de-duplicated and sorted, so a list in
// configuration that differs only in case or repeats keeps its configured
// spelling when the server's list is its normal form (no perpetual diff).
func flattenGatewayScope(row map[string]any, prior gatewayScopeFields) gatewayScopeFields {
	next := nullGatewayScope()
	if kind := tfhelpers.GetString(row, "kind"); kind != "" {
		next.Kind = types.StringValue(kind)
	}
	next.AllowedAgents = keepIfSameScope(prior.AllowedAgents, tfhelpers.GetStringSlice(row, "allowed_agents"))
	next.AllowedTools = keepIfSameScope(prior.AllowedTools, tfhelpers.GetStringSlice(row, "allowed_tools"))
	return next
}

func keepIfSameScope(prior types.Set, server []string) types.Set {
	if have := setStrings(prior); len(have) > 0 && len(server) > 0 {
		seen := map[string]bool{}
		norm := []string{}
		for _, v := range have {
			v = strings.ToLower(v)
			if !seen[v] {
				seen[v] = true
				norm = append(norm, v)
			}
		}
		sort.Strings(norm)
		want := append([]string(nil), server...)
		sort.Strings(want)
		if strings.Join(norm, "\x00") == strings.Join(want, "\x00") {
			return prior
		}
	}
	return stringSetValue(server)
}
