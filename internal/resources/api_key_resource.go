package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &apiKeyResource{}
var _ resource.ResourceWithImportState = &apiKeyResource{}

const (
	apiKeyScopeFleet        = "fleet"
	apiKeyScopeEndpoint     = "endpoint"
	apiKeyScopeAgent        = "agent"
	apiKeyScopeOrganization = "organization"
)

type apiKeyResource struct {
	client   *client.Client
	tenantID string
}

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

func NewAPIKeyResource() resource.Resource {
	return &apiKeyResource{}
}

func (r *apiKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_key"
}

func (r *apiKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Creates and manages tenant-scoped JIT Thoth API keys.",
		Attributes: map[string]schema.Attribute{
			"id":        schema.StringAttribute{Computed: true, Description: "Resource ID (key ID).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id": schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"key_id":    schema.StringAttribute{Computed: true, Description: "GovAPI key identifier."},
			"name":      schema.StringAttribute{Optional: true, Description: "Display name for the API key.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"scope_level": schema.StringAttribute{
				Required: true,
				Description: "Scope level for issued key. Supported in provider: fleet, endpoint, agent. " +
					"Organization keys must be created out-of-band via thothctl.",
				DeprecationMessage: "Use thoth_fleet_api_key, thoth_endpoint_api_key, or thoth_agent_api_key instead.",
				PlanModifiers:      []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.OneOf(
						apiKeyScopeFleet,
						apiKeyScopeEndpoint,
						apiKeyScopeAgent,
						apiKeyScopeOrganization,
					),
				},
			},
			"scope_target_id": schema.StringAttribute{Optional: true, Description: "Target ID for the selected scope level. Required for fleet, endpoint, and agent scopes.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"permissions":     schema.ListAttribute{Required: true, ElementType: types.StringType, Description: "Allowed permissions: read, write, execute.", PlanModifiers: []planmodifier.List{listplanmodifier.RequiresReplace()}},
			"ttl_seconds":     schema.Int64Attribute{Optional: true, Description: "TTL in seconds for key expiry.", PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()}},
			"jit_reason":      schema.StringAttribute{Optional: true, Description: "Audit reason for just-in-time issuance.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"api_key":         schema.StringAttribute{Computed: true, Sensitive: true, Description: "One-time plaintext API key (returned only on create)."},
			"prefix":          schema.StringAttribute{Computed: true, Description: "Key prefix for operator identification."},
			"created_at":      schema.StringAttribute{Computed: true, Description: "Creation timestamp."},
			"expires_at":      schema.StringAttribute{Computed: true, Description: "Expiry timestamp."},
			"last_used_at":    schema.StringAttribute{Computed: true, Description: "Last authorization timestamp."},
			"active":          schema.BoolAttribute{Computed: true, Description: "Whether key is currently active and not expired/revoked."},
		},
	}
}

func (r *apiKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *apiKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan apiKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	scopeLevel := strings.ToLower(strings.TrimSpace(plan.ScopeLevel.ValueString()))
	scopeTargetID := strings.TrimSpace(plan.ScopeTargetID.ValueString())
	if err := validateAPIKeyScopeForCreate(scopeLevel, scopeTargetID); err != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("scope_level"),
			"Unsupported API key scope for provider-managed creation",
			err.Error(),
		)
		return
	}

	payload := map[string]any{
		"scope_level": scopeLevel,
	}
	if !plan.Name.IsNull() && !plan.Name.IsUnknown() {
		payload["name"] = plan.Name.ValueString()
	}
	if scopeTargetID != "" {
		payload["scope_target_id"] = scopeTargetID
	}
	if !plan.TTLSeconds.IsNull() && !plan.TTLSeconds.IsUnknown() {
		payload["ttl_seconds"] = plan.TTLSeconds.ValueInt64()
	}
	if !plan.JITReason.IsNull() && !plan.JITReason.IsUnknown() {
		payload["jit_reason"] = plan.JITReason.ValueString()
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

	next := flattenAPIKeyCreated(row, plan, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func validateAPIKeyScopeForCreate(scopeLevel string, scopeTargetID string) error {
	switch scopeLevel {
	case apiKeyScopeOrganization:
		return errorsForOrganizationScope()
	case apiKeyScopeFleet, apiKeyScopeEndpoint, apiKeyScopeAgent:
		if scopeTargetID == "" {
			return fmt.Errorf("scope_target_id must be set when scope_level is %q", scopeLevel)
		}
		return nil
	default:
		return fmt.Errorf(
			"invalid scope_level %q: supported values are %q, %q, %q",
			scopeLevel,
			apiKeyScopeFleet,
			apiKeyScopeEndpoint,
			apiKeyScopeAgent,
		)
	}
}

func errorsForOrganizationScope() error {
	return fmt.Errorf(
		"organization-scoped API keys cannot be created by this provider. " +
			"Create org keys with thothctl (for example: `thothctl api-keys create --scope organization ...`) " +
			"and provide them to Terraform/Pulumi via THOTH_API_KEY or org_api_key.",
	)
}

func (r *apiKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
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
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *apiKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// All configurable attributes require replacement; preserve state if update is reached.
	var plan apiKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *apiKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
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

func (r *apiKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	keyID := strings.TrimSpace(req.ID)
	if keyID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use key_id as import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), keyID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key_id"), keyID)...)
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
