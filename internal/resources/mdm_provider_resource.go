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

var _ resource.Resource = &mdmProviderResource{}
var _ resource.ResourceWithImportState = &mdmProviderResource{}

type mdmProviderResource struct {
	client   *client.Client
	tenantID string
}

type mdmProviderModel struct {
	ID              types.String `tfsdk:"id"`
	TenantID        types.String `tfsdk:"tenant_id"`
	ProviderName    types.String `tfsdk:"provider_name"`
	Name            types.String `tfsdk:"name"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	ConfigJSON      types.String `tfsdk:"config_json"`
	Status          types.String `tfsdk:"status"`
	LastSyncAt      types.String `tfsdk:"last_sync_at"`
	LastSyncStatus  types.String `tfsdk:"last_sync_status"`
	LastSyncJobID   types.String `tfsdk:"last_sync_job_id"`
	LastError       types.String `tfsdk:"last_error"`
	SyncedEndpoints types.Int64  `tfsdk:"synced_endpoints"`
	CreatedAt       types.String `tfsdk:"created_at"`
	UpdatedAt       types.String `tfsdk:"updated_at"`
}

func NewMDMProviderResource() resource.Resource {
	return &mdmProviderResource{}
}

func (r *mdmProviderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mdm_provider"
}

func (r *mdmProviderResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a tenant-scoped MDM provider integration.",
		Attributes: map[string]schema.Attribute{
			"id":               schema.StringAttribute{Computed: true, Description: "Resource ID (provider slug).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":        schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"provider_name":    schema.StringAttribute{Required: true, Description: "Provider slug: jamf, intune, workspace_one, custom.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"name":             schema.StringAttribute{Optional: true, Description: "Display name for the provider."},
			"enabled":          schema.BoolAttribute{Optional: true, Description: "Enable the provider integration."},
			"config_json":      schema.StringAttribute{Optional: true, Sensitive: true, Description: "Provider configuration JSON object."},
			"status":           schema.StringAttribute{Computed: true, Description: "Provider status from GovAPI."},
			"last_sync_at":     schema.StringAttribute{Computed: true, Description: "Last sync timestamp."},
			"last_sync_status": schema.StringAttribute{Computed: true, Description: "Last sync status."},
			"last_sync_job_id": schema.StringAttribute{Computed: true, Description: "Last sync job identifier."},
			"last_error":       schema.StringAttribute{Computed: true, Description: "Last error message from provider sync."},
			"synced_endpoints": schema.Int64Attribute{Computed: true, Description: "Count of endpoints synchronized on latest run."},
			"created_at":       schema.StringAttribute{Computed: true, Description: "Creation timestamp."},
			"updated_at":       schema.StringAttribute{Computed: true, Description: "Update timestamp."},
		},
	}
}

func (r *mdmProviderResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *mdmProviderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan mdmProviderModel
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

func (r *mdmProviderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state mdmProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	provider := strings.TrimSpace(state.ProviderName.ValueString())
	row, found, err := r.findProvider(ctx, provider)
	if err != nil {
		resp.Diagnostics.AddError("Error reading MDM provider", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	next := flattenMDMProvider(row, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *mdmProviderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan mdmProviderModel
	var state mdmProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, ok := r.upsert(ctx, plan, state, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *mdmProviderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state mdmProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := map[string]any{
		"provider": state.ProviderName.ValueString(),
		"name":     state.Name.ValueString(),
		"enabled":  false,
	}
	if !state.ConfigJSON.IsNull() && !state.ConfigJSON.IsUnknown() && strings.TrimSpace(state.ConfigJSON.ValueString()) != "" {
		cfg, err := tfhelpers.ParseJSONObject(state.ConfigJSON.ValueString())
		if err != nil {
			resp.Diagnostics.AddWarning("Unable to parse config_json during delete", err.Error())
		} else {
			payload["config"] = cfg
		}
	}
	_, err := r.client.UpsertMDMProvider(ctx, payload)
	if err != nil {
		resp.Diagnostics.AddWarning("Failed to disable MDM provider during delete", err.Error())
	}
}

func (r *mdmProviderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(strings.TrimSpace(req.ID), "/")
	providerID := parts[len(parts)-1]
	if providerID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use provider slug or tenant/provider.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), providerID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("provider_name"), providerID)...)
}

func (r *mdmProviderResource) upsert(ctx context.Context, plan, prior mdmProviderModel, diags *diag.Diagnostics) (mdmProviderModel, bool) {
	payload := map[string]any{
		"provider": strings.TrimSpace(plan.ProviderName.ValueString()),
	}
	if payload["provider"] == "" {
		diags.AddAttributeError(path.Root("provider_name"), "Missing provider", "provider_name must be set.")
		return mdmProviderModel{}, false
	}
	if !plan.Name.IsNull() && !plan.Name.IsUnknown() {
		payload["name"] = plan.Name.ValueString()
	}
	if !plan.Enabled.IsNull() && !plan.Enabled.IsUnknown() {
		payload["enabled"] = plan.Enabled.ValueBool()
	} else {
		payload["enabled"] = true
	}
	if !plan.ConfigJSON.IsNull() && !plan.ConfigJSON.IsUnknown() && strings.TrimSpace(plan.ConfigJSON.ValueString()) != "" {
		cfg, err := tfhelpers.ParseJSONObject(plan.ConfigJSON.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("config_json"), "Invalid JSON", err.Error())
			return mdmProviderModel{}, false
		}
		payload["config"] = cfg
	} else if !prior.ConfigJSON.IsNull() && !prior.ConfigJSON.IsUnknown() && strings.TrimSpace(prior.ConfigJSON.ValueString()) != "" {
		cfg, err := tfhelpers.ParseJSONObject(prior.ConfigJSON.ValueString())
		if err == nil {
			payload["config"] = cfg
		}
	}

	row, err := r.client.UpsertMDMProvider(ctx, payload)
	if err != nil {
		diags.AddError("Error upserting MDM provider", err.Error())
		return mdmProviderModel{}, false
	}
	return flattenMDMProvider(row, plan, r.tenantID), true
}

func (r *mdmProviderResource) findProvider(ctx context.Context, provider string) (map[string]any, bool, error) {
	rows, err := r.client.ListMDMProviders(ctx)
	if err != nil {
		return nil, false, err
	}
	row, found := tfhelpers.FindByStringField(rows, "provider", provider)
	return row, found, nil
}

func flattenMDMProvider(row map[string]any, current mdmProviderModel, tenantID string) mdmProviderModel {
	next := current
	next.ID = types.StringValue(tfhelpers.GetString(row, "provider"))
	next.TenantID = types.StringValue(tenantID)
	next.ProviderName = types.StringValue(tfhelpers.GetString(row, "provider"))
	if v := strings.TrimSpace(tfhelpers.GetString(row, "name")); v != "" {
		next.Name = types.StringValue(v)
	}
	next.Enabled = types.BoolValue(tfhelpers.GetBool(row, "enabled"))
	// Preserve operator-provided sensitive payload exactly; GovAPI may redact or reorder.
	next.ConfigJSON = current.ConfigJSON
	next.Status = nullableString(row, "status")
	next.LastSyncAt = nullableString(row, "last_sync_at")
	next.LastSyncStatus = nullableString(row, "last_sync_status")
	next.LastSyncJobID = nullableString(row, "last_sync_job_id")
	next.LastError = nullableString(row, "last_error")
	next.SyncedEndpoints = types.Int64Value(tfhelpers.GetInt64(row, "synced_endpoints"))
	next.CreatedAt = nullableString(row, "created_at")
	next.UpdatedAt = nullableString(row, "updated_at")
	return next
}

func nullableString(m map[string]any, key string) types.String {
	v := strings.TrimSpace(tfhelpers.GetString(m, key))
	if v == "" {
		return types.StringNull()
	}
	return types.StringValue(v)
}
