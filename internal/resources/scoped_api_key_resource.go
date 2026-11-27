package resources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &scopedAPIKeyResource{}
var _ resource.ResourceWithImportState = &scopedAPIKeyResource{}
var _ resource.ResourceWithValidateConfig = &scopedAPIKeyResource{}

type scopedAPIKeyResource struct {
	client       *client.Client
	tenantID     string
	typeSuffix   string
	scopeLevel   string
	targetIDName string
}

func NewFleetAPIKeyResource() resource.Resource {
	return &scopedAPIKeyResource{
		typeSuffix:   "_fleet_api_key",
		scopeLevel:   apiKeyScopeFleet,
		targetIDName: "Fleet",
	}
}

func NewEndpointAPIKeyResource() resource.Resource {
	return &scopedAPIKeyResource{
		typeSuffix:   "_endpoint_api_key",
		scopeLevel:   apiKeyScopeEndpoint,
		targetIDName: "Endpoint",
	}
}

func NewAgentAPIKeyResource() resource.Resource {
	return &scopedAPIKeyResource{
		typeSuffix:   "_agent_api_key",
		scopeLevel:   apiKeyScopeAgent,
		targetIDName: "Agent",
	}
}

func (r *scopedAPIKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + r.typeSuffix
}

func (r *scopedAPIKeyResource) isEndpoint() bool { return r.scopeLevel == apiKeyScopeEndpoint }

func (r *scopedAPIKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Creates and manages scoped JIT Thoth API keys.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Resource ID (key ID).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant_id": schema.StringAttribute{
				Computed:    true,
				Description: "Tenant ID from provider configuration.",
			},
			"key_id": schema.StringAttribute{
				Computed:    true,
				Description: "GovAPI key identifier.",
			},
			"name": schema.StringAttribute{
				Optional:      true,
				Description:   "Display name for the API key.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"scope_level": schema.StringAttribute{
				Computed:    true,
				Description: "Fixed scope for this resource type.",
			},
			"scope_target_id": schema.StringAttribute{
				Required:      true,
				Description:   r.targetIDName + " ID targeted by this API key scope.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"permissions": schema.ListAttribute{
				Required:      true,
				ElementType:   types.StringType,
				Description:   "Allowed permissions: read, write, execute.",
				PlanModifiers: []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
			"ttl_seconds": schema.Int64Attribute{
				Optional:      true,
				Description:   "TTL in seconds for key expiry.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"jit_reason": schema.StringAttribute{
				Optional:      true,
				Description:   "Audit reason for just-in-time issuance.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"api_key": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "One-time plaintext API key (returned only on create).",
			},
			"prefix": schema.StringAttribute{
				Computed:    true,
				Description: "Key prefix for operator identification.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Creation timestamp.",
			},
			"expires_at": schema.StringAttribute{
				Computed:    true,
				Description: "Expiry timestamp.",
			},
			"last_used_at": schema.StringAttribute{
				Computed:    true,
				Description: "Last authorization timestamp.",
			},
			"active": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether key is currently active and not expired/revoked.",
			},
		},
	}
	if r.isEndpoint() {
		resp.Schema.Attributes["kind"] = schema.StringAttribute{
			Optional: true,
			Description: "Key kind. Omit for an ordinary key. `mcp_gateway` issues the runtime key of the customer-hosted MCP gateway: " +
				"it needs `permissions = [\"execute\"]` and both `allowed_agents` and `allowed_tools`. Changing it replaces the key.",
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		}
		resp.Schema.Attributes["allowed_agents"] = schema.SetAttribute{
			Optional:    true,
			ElementType: types.StringType,
			Description: "Required when `kind = \"mcp_gateway\"`, rejected otherwise. Exact ids of agents under this endpoint (1 to 128 printable ASCII characters, " +
				"no space, `*`, `/` or `\\`) that the key may act for. At most 64. The server lower-cases the ids; every id must already be on the endpoint. Changing it replaces the key.",
			PlanModifiers: []planmodifier.Set{setplanmodifier.RequiresReplace()},
		}
		resp.Schema.Attributes["allowed_tools"] = schema.SetAttribute{
			Optional:    true,
			ElementType: types.StringType,
			Description: "Required when `kind = \"mcp_gateway\"`, rejected otherwise. Tools the key may ask about, each `<upstream>__<tool>` exactly, " +
				"or `<upstream>__<tool prefix>*` with one trailing `*` after at least 3 characters. The upstream is letters, digits, `-` and `_` (no `__`, not ending in `_`); " +
				"the tool is letters, digits and `_ - . :` and does not start with `_`; each part is at most 128 characters. At most 64. The server lower-cases the names. Changing it replaces the key.",
			PlanModifiers: []planmodifier.Set{setplanmodifier.RequiresReplace()},
		}
	}
}

// ValidateConfig applies the gateway key rules at plan time, with the same
// rules as the server, so a mistake is reported before anything is created.
func (r *scopedAPIKeyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	if !r.isEndpoint() {
		return
	}
	var kind types.String
	var agents, tools types.Set
	var perms types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("kind"), &kind)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("allowed_agents"), &agents)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("allowed_tools"), &tools)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("permissions"), &perms)...)
	if resp.Diagnostics.HasError() || kind.IsUnknown() || agents.IsUnknown() || tools.IsUnknown() || perms.IsUnknown() {
		return
	}
	for _, set := range []types.Set{agents, tools} {
		for _, el := range set.Elements() {
			if el.IsUnknown() {
				return
			}
		}
	}
	var permValues []string
	for _, el := range perms.Elements() {
		s, ok := el.(types.String)
		if !ok || s.IsUnknown() {
			return
		}
		permValues = append(permValues, s.ValueString())
	}
	if err := validateGatewayKeyKind(kind.ValueString(), r.scopeLevel, permValues); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("kind"), "Invalid gateway key", err.Error())
		return
	}
	agentValues, toolValues := optionalStrings(agents), optionalStrings(tools)
	if kind.ValueString() != gatewayKeyKind {
		if agentValues != nil {
			resp.Diagnostics.AddAttributeError(path.Root("allowed_agents"), "Invalid gateway key scope", `allowed_agents is accepted only with kind = "mcp_gateway"`)
		}
		if toolValues != nil {
			resp.Diagnostics.AddAttributeError(path.Root("allowed_tools"), "Invalid gateway key scope", `allowed_tools is accepted only with kind = "mcp_gateway"`)
		}
		return
	}
	if _, err := normalizeGatewayKeyScopeList("allowed_agents", agentValues, false); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("allowed_agents"), "Invalid gateway key scope", err.Error())
	}
	if _, err := normalizeGatewayKeyScopeList("allowed_tools", toolValues, true); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("allowed_tools"), "Invalid gateway key scope", err.Error())
	}
}

// optionalStrings is nil for a null set and a non-nil slice otherwise, so an
// empty set can be told from an omitted one.
func optionalStrings(set types.Set) []string {
	if set.IsNull() || set.IsUnknown() {
		return nil
	}
	return append([]string{}, setStrings(set)...)
}

type stateGetter interface {
	Get(ctx context.Context, target any) diag.Diagnostics
}

type stateSetter interface {
	Set(ctx context.Context, val any) diag.Diagnostics
}

func (r *scopedAPIKeyResource) loadModel(ctx context.Context, src stateGetter) (apiKeyModel, gatewayScopeFields, diag.Diagnostics) {
	if r.isEndpoint() {
		var m endpointAPIKeyModel
		d := src.Get(ctx, &m)
		return m.apiKeyModel, m.gatewayScopeFields, d
	}
	var m apiKeyModel
	d := src.Get(ctx, &m)
	return m, nullGatewayScope(), d
}

func (r *scopedAPIKeyResource) storeModel(ctx context.Context, dst stateSetter, m apiKeyModel, g gatewayScopeFields) diag.Diagnostics {
	if r.isEndpoint() {
		return dst.Set(ctx, &endpointAPIKeyModel{apiKeyModel: m, gatewayScopeFields: g})
	}
	return dst.Set(ctx, &m)
}

func (r *scopedAPIKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *scopedAPIKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	plan, gateway, diags := r.loadModel(ctx, req.Plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	scopeTargetID := strings.TrimSpace(plan.ScopeTargetID.ValueString())
	if scopeTargetID == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("scope_target_id"),
			"Missing scope_target_id",
			r.targetIDName+" scoped keys require scope_target_id.",
		)
		return
	}

	payload := map[string]any{
		"scope_level":     r.scopeLevel,
		"scope_target_id": scopeTargetID,
	}
	if !plan.Name.IsNull() && !plan.Name.IsUnknown() {
		payload["name"] = strings.TrimSpace(plan.Name.ValueString())
	}
	if !plan.TTLSeconds.IsNull() && !plan.TTLSeconds.IsUnknown() {
		payload["ttl_seconds"] = plan.TTLSeconds.ValueInt64()
	}
	if !plan.JITReason.IsNull() && !plan.JITReason.IsUnknown() {
		payload["jit_reason"] = strings.TrimSpace(plan.JITReason.ValueString())
	}

	var perms []string
	resp.Diagnostics.Append(plan.Permissions.ElementsAs(ctx, &perms, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	permValues := make([]any, 0, len(perms))
	for _, p := range perms {
		permValues = append(permValues, p)
	}
	payload["permissions"] = permValues

	if r.isEndpoint() {
		if err := addGatewayScopePayload(payload, gateway, perms, r.scopeLevel); err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("kind"), "Invalid gateway key", err.Error())
			return
		}
	}

	row, err := r.client.CreateAPIKey(ctx, payload)
	if err != nil {
		resp.Diagnostics.AddError("Error creating API key", err.Error())
		return
	}

	plan.ScopeLevel = types.StringValue(r.scopeLevel)
	plan.ScopeTargetID = types.StringValue(scopeTargetID)
	next := flattenAPIKeyCreated(row, plan, r.tenantID)
	next.ScopeLevel = types.StringValue(r.scopeLevel)
	resp.Diagnostics.Append(r.storeModel(ctx, &resp.State, next, gateway)...)
}

// addGatewayScopePayload adds kind, allowed_agents and allowed_tools to the
// create request, after the same checks the plan made.
func addGatewayScopePayload(payload map[string]any, g gatewayScopeFields, perms []string, scopeLevel string) error {
	kind := ""
	if !g.Kind.IsNull() && !g.Kind.IsUnknown() {
		kind = g.Kind.ValueString()
	}
	if err := validateGatewayKeyKind(kind, scopeLevel, perms); err != nil {
		return err
	}
	agents, tools, err := normalizeGatewayKeyScope(kind, optionalStrings(g.AllowedAgents), optionalStrings(g.AllowedTools))
	if err != nil {
		return err
	}
	if kind == "" {
		return nil
	}
	payload["kind"] = kind
	payload["allowed_agents"] = agents
	payload["allowed_tools"] = tools
	return nil
}

func (r *scopedAPIKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	state, gateway, diags := r.loadModel(ctx, req.State)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	rows, err := r.client.ListAPIKeys(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing API keys", err.Error())
		return
	}
	row, found := tfhelpers.FindByStringField(rows, "key_id", state.KeyID.ValueString())
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	next := flattenAPIKeyInfo(row, state, r.tenantID)
	if !strings.EqualFold(next.ScopeLevel.ValueString(), r.scopeLevel) {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(r.storeModel(ctx, &resp.State, next, flattenGatewayScope(row, gateway))...)
}

func (r *scopedAPIKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	plan, gateway, diags := r.loadModel(ctx, req.Plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(r.storeModel(ctx, &resp.State, plan, gateway)...)
}

func (r *scopedAPIKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	state, _, diags := r.loadModel(ctx, req.State)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.RevokeAPIKey(ctx, state.KeyID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Error revoking API key", err.Error())
	}
}

func (r *scopedAPIKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	keyID := strings.TrimSpace(req.ID)
	if keyID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use key_id as import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), keyID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key_id"), keyID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("scope_level"), r.scopeLevel)...)
}
