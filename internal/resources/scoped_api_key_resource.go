package resources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &scopedAPIKeyResource{}
var _ resource.ResourceWithImportState = &scopedAPIKeyResource{}

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
	var plan apiKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
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

	row, err := r.client.CreateAPIKey(ctx, payload)
	if err != nil {
		resp.Diagnostics.AddError("Error creating API key", err.Error())
		return
	}

	plan.ScopeLevel = types.StringValue(r.scopeLevel)
	plan.ScopeTargetID = types.StringValue(scopeTargetID)
	next := flattenAPIKeyCreated(row, plan, r.tenantID)
	next.ScopeLevel = types.StringValue(r.scopeLevel)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *scopedAPIKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state apiKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
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
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *scopedAPIKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan apiKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *scopedAPIKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state apiKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
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
