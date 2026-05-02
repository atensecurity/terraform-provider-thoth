package resources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &browserPolicyResource{}
var _ resource.ResourceWithImportState = &browserPolicyResource{}

type browserPolicyResource struct {
	client   *client.Client
	tenantID string
}

type browserPolicyModel struct {
	ID                 types.String `tfsdk:"id"`
	TenantID           types.String `tfsdk:"tenant_id"`
	PolicyID           types.String `tfsdk:"policy_id"`
	Name               types.String `tfsdk:"name"`
	Provider           types.String `tfsdk:"provider"`
	EnforcementMode    types.String `tfsdk:"enforcement_mode"`
	Active             types.Bool   `tfsdk:"active"`
	Version            types.Int64  `tfsdk:"version"`
	PolicyJSON         types.String `tfsdk:"policy_json"`
	MetadataJSON       types.String `tfsdk:"metadata_json"`
	CompiledPolicyJSON types.String `tfsdk:"compiled_policy_json"`
	CreatedBy          types.String `tfsdk:"created_by"`
	UpdatedBy          types.String `tfsdk:"updated_by"`
	CreatedAt          types.String `tfsdk:"created_at"`
	UpdatedAt          types.String `tfsdk:"updated_at"`
}

func NewBrowserPolicyResource() resource.Resource {
	return &browserPolicyResource{}
}

func (r *browserPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_browser_policy"
}

func (r *browserPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages browser policy definitions for a tenant/provider.",
		Attributes: map[string]schema.Attribute{
			"id":                   schema.StringAttribute{Computed: true, Description: "Resource identifier (policy ID).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":            schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"policy_id":            schema.StringAttribute{Optional: true, Computed: true, Description: "Policy ID. If omitted on create, GovAPI generates one."},
			"name":                 schema.StringAttribute{Required: true, Description: "Policy display name."},
			"provider":             schema.StringAttribute{Required: true, Description: "Browser provider slug.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"enforcement_mode":     schema.StringAttribute{Optional: true, Description: "Policy mode: monitor or enforce."},
			"active":               schema.BoolAttribute{Optional: true, Description: "Whether the policy is active."},
			"version":              schema.Int64Attribute{Optional: true, Description: "Optional explicit policy version."},
			"policy_json":          schema.StringAttribute{Required: true, Description: "Policy JSON object."},
			"metadata_json":        schema.StringAttribute{Optional: true, Description: "Arbitrary metadata JSON object."},
			"compiled_policy_json": schema.StringAttribute{Computed: true, Description: "Compiled provider-native policy JSON from GovAPI."},
			"created_by":           schema.StringAttribute{Optional: true, Description: "Override created_by audit value."},
			"updated_by":           schema.StringAttribute{Optional: true, Description: "Override updated_by audit value."},
			"created_at":           schema.StringAttribute{Computed: true, Description: "Creation timestamp."},
			"updated_at":           schema.StringAttribute{Computed: true, Description: "Update timestamp."},
		},
	}
}

func (r *browserPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *browserPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan browserPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, ok := r.upsert(ctx, plan, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *browserPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state browserPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	row, found, err := r.findPolicy(ctx, state.PolicyID.ValueString(), state.Provider.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading browser policy", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	next := flattenBrowserPolicy(row, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *browserPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan browserPolicyModel
	var state browserPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if (plan.PolicyID.IsNull() || plan.PolicyID.IsUnknown()) && !state.PolicyID.IsNull() && !state.PolicyID.IsUnknown() {
		plan.PolicyID = state.PolicyID
	}
	next, ok := r.upsert(ctx, plan, state, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *browserPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state browserPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := map[string]any{
		"policy_id": state.PolicyID.ValueString(),
		"name":      state.Name.ValueString(),
		"provider":  state.Provider.ValueString(),
		"active":    false,
	}
	if !state.PolicyJSON.IsNull() && !state.PolicyJSON.IsUnknown() {
		policyObj, err := tfhelpers.ParseJSONObject(state.PolicyJSON.ValueString())
		if err == nil {
			payload["policy"] = policyObj
		}
	}
	if !state.MetadataJSON.IsNull() && !state.MetadataJSON.IsUnknown() {
		metaObj, err := tfhelpers.ParseJSONObject(state.MetadataJSON.ValueString())
		if err == nil {
			payload["metadata"] = metaObj
		}
	}
	_, err := r.client.UpsertBrowserPolicy(ctx, payload)
	if err != nil {
		resp.Diagnostics.AddWarning("Failed to deactivate browser policy on delete", err.Error())
	}
}

func (r *browserPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	policyID := strings.TrimSpace(req.ID)
	if policyID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use policy_id as import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), policyID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("policy_id"), policyID)...)
}

func (r *browserPolicyResource) upsert(ctx context.Context, plan, prior browserPolicyModel, diags *diag.Diagnostics) (browserPolicyModel, bool) {
	provider := strings.TrimSpace(plan.Provider.ValueString())
	if provider == "" {
		diags.AddAttributeError(path.Root("provider"), "Missing provider", "provider must be set.")
		return browserPolicyModel{}, false
	}
	if strings.TrimSpace(plan.PolicyJSON.ValueString()) == "" {
		diags.AddAttributeError(path.Root("policy_json"), "Missing policy_json", "policy_json must contain a JSON object.")
		return browserPolicyModel{}, false
	}
	policyObj, err := tfhelpers.ParseJSONObject(plan.PolicyJSON.ValueString())
	if err != nil {
		diags.AddAttributeError(path.Root("policy_json"), "Invalid JSON", err.Error())
		return browserPolicyModel{}, false
	}

	payload := map[string]any{
		"name":     strings.TrimSpace(plan.Name.ValueString()),
		"provider": provider,
		"policy":   policyObj,
	}
	if payload["name"] == "" {
		diags.AddAttributeError(path.Root("name"), "Missing name", "name must be set.")
		return browserPolicyModel{}, false
	}
	if !plan.PolicyID.IsNull() && !plan.PolicyID.IsUnknown() {
		payload["policy_id"] = plan.PolicyID.ValueString()
	} else if !prior.PolicyID.IsNull() && !prior.PolicyID.IsUnknown() {
		payload["policy_id"] = prior.PolicyID.ValueString()
	}
	if !plan.EnforcementMode.IsNull() && !plan.EnforcementMode.IsUnknown() {
		payload["enforcement_mode"] = plan.EnforcementMode.ValueString()
	}
	if !plan.Active.IsNull() && !plan.Active.IsUnknown() {
		payload["active"] = plan.Active.ValueBool()
	} else {
		payload["active"] = true
	}
	if !plan.Version.IsNull() && !plan.Version.IsUnknown() {
		payload["version"] = plan.Version.ValueInt64()
	}
	if !plan.MetadataJSON.IsNull() && !plan.MetadataJSON.IsUnknown() && strings.TrimSpace(plan.MetadataJSON.ValueString()) != "" {
		metaObj, err := tfhelpers.ParseJSONObject(plan.MetadataJSON.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("metadata_json"), "Invalid JSON", err.Error())
			return browserPolicyModel{}, false
		}
		payload["metadata"] = metaObj
	}
	if !plan.CreatedBy.IsNull() && !plan.CreatedBy.IsUnknown() {
		payload["created_by"] = plan.CreatedBy.ValueString()
	}
	if !plan.UpdatedBy.IsNull() && !plan.UpdatedBy.IsUnknown() {
		payload["updated_by"] = plan.UpdatedBy.ValueString()
	}

	row, err := r.client.UpsertBrowserPolicy(ctx, payload)
	if err != nil {
		diags.AddError("Error upserting browser policy", err.Error())
		return browserPolicyModel{}, false
	}
	return flattenBrowserPolicy(row, plan, r.tenantID), true
}

func (r *browserPolicyResource) findPolicy(ctx context.Context, policyID, provider string) (map[string]any, bool, error) {
	rows, err := r.client.ListBrowserPolicies(ctx, provider)
	if err != nil {
		return nil, false, err
	}
	row, found := tfhelpers.FindByStringField(rows, "policy_id", policyID)
	return row, found, nil
}

func flattenBrowserPolicy(row map[string]any, current browserPolicyModel, tenantID string) browserPolicyModel {
	next := current
	policyID := tfhelpers.GetString(row, "policy_id")
	next.ID = types.StringValue(policyID)
	next.PolicyID = types.StringValue(policyID)
	next.TenantID = types.StringValue(tenantID)
	next.Name = nullableString(row, "name")
	next.Provider = nullableString(row, "provider")
	next.EnforcementMode = nullableString(row, "enforcement_mode")
	next.Active = types.BoolValue(tfhelpers.GetBool(row, "active"))
	next.Version = types.Int64Value(tfhelpers.GetInt64(row, "version"))
	if raw := row["policy"]; raw != nil {
		next.PolicyJSON = types.StringValue(tfhelpers.ToJSONString(raw))
	}
	if raw := row["metadata"]; raw != nil {
		next.MetadataJSON = types.StringValue(tfhelpers.ToJSONString(raw))
	}
	if raw := row["compiled_policy"]; raw != nil {
		next.CompiledPolicyJSON = types.StringValue(tfhelpers.ToJSONString(raw))
	}
	next.CreatedBy = nullableString(row, "created_by")
	next.UpdatedBy = nullableString(row, "updated_by")
	next.CreatedAt = nullableString(row, "created_at")
	next.UpdatedAt = nullableString(row, "updated_at")
	return next
}
