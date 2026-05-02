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

var _ resource.Resource = &browserProviderResource{}
var _ resource.ResourceWithImportState = &browserProviderResource{}

type browserProviderResource struct {
	client   *client.Client
	tenantID string
}

type browserProviderModel struct {
	ID           types.String `tfsdk:"id"`
	TenantID     types.String `tfsdk:"tenant_id"`
	ProviderName types.String `tfsdk:"provider_name"`
	Name         types.String `tfsdk:"name"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	Status       types.String `tfsdk:"status"`
	ConfigJSON   types.String `tfsdk:"config_json"`
	LastError    types.String `tfsdk:"last_error"`
	CreatedAt    types.String `tfsdk:"created_at"`
	UpdatedAt    types.String `tfsdk:"updated_at"`
}

func NewBrowserProviderResource() resource.Resource {
	return &browserProviderResource{}
}

func (r *browserProviderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_browser_provider"
}

func (r *browserProviderResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages browser policy provider connectivity for a tenant.",
		Attributes: map[string]schema.Attribute{
			"id":            schema.StringAttribute{Computed: true, Description: "Resource ID (provider slug).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":     schema.StringAttribute{Computed: true, Description: "Tenant ID from provider config."},
			"provider_name": schema.StringAttribute{Required: true, Description: "Browser provider slug: chrome, firefox, safari, island.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"name":          schema.StringAttribute{Optional: true, Description: "Display name for this provider integration."},
			"enabled":       schema.BoolAttribute{Optional: true, Description: "Enable provider integration."},
			"status":        schema.StringAttribute{Optional: true, Description: "Provider status hint (connected, degraded, disconnected)."},
			"config_json":   schema.StringAttribute{Optional: true, Sensitive: true, Description: "Provider-specific config JSON object."},
			"last_error":    schema.StringAttribute{Optional: true, Description: "Last integration error string."},
			"created_at":    schema.StringAttribute{Computed: true, Description: "Creation timestamp."},
			"updated_at":    schema.StringAttribute{Computed: true, Description: "Last update timestamp."},
		},
	}
}

func (r *browserProviderResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *browserProviderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan browserProviderModel
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

func (r *browserProviderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state browserProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	rows, err := r.client.ListBrowserProviders(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading browser providers", err.Error())
		return
	}
	row, found := tfhelpers.FindByStringField(rows, "provider", state.ProviderName.ValueString())
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	next := flattenBrowserProvider(row, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *browserProviderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan browserProviderModel
	var state browserProviderModel
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

func (r *browserProviderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state browserProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := map[string]any{"provider": state.ProviderName.ValueString(), "enabled": false}
	if !state.Name.IsNull() && !state.Name.IsUnknown() {
		payload["name"] = state.Name.ValueString()
	}
	if !state.ConfigJSON.IsNull() && !state.ConfigJSON.IsUnknown() && strings.TrimSpace(state.ConfigJSON.ValueString()) != "" {
		cfg, err := tfhelpers.ParseJSONObject(state.ConfigJSON.ValueString())
		if err == nil {
			payload["config"] = cfg
		}
	}
	_, err := r.client.UpsertBrowserProvider(ctx, payload)
	if err != nil {
		resp.Diagnostics.AddWarning("Failed to disable browser provider on delete", err.Error())
	}
}

func (r *browserProviderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(strings.TrimSpace(req.ID), "/")
	providerID := parts[len(parts)-1]
	if providerID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use provider slug or tenant/provider.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), providerID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("provider_name"), providerID)...)
}

func (r *browserProviderResource) upsert(ctx context.Context, plan, prior browserProviderModel, diags *diag.Diagnostics) (browserProviderModel, bool) {
	provider := strings.TrimSpace(plan.ProviderName.ValueString())
	if provider == "" {
		diags.AddAttributeError(path.Root("provider_name"), "Missing provider", "provider_name must be set.")
		return browserProviderModel{}, false
	}

	payload := map[string]any{"provider": provider}
	if !plan.Name.IsNull() && !plan.Name.IsUnknown() {
		payload["name"] = plan.Name.ValueString()
	}
	if !plan.Enabled.IsNull() && !plan.Enabled.IsUnknown() {
		payload["enabled"] = plan.Enabled.ValueBool()
	} else {
		payload["enabled"] = true
	}
	if !plan.Status.IsNull() && !plan.Status.IsUnknown() {
		payload["status"] = plan.Status.ValueString()
	}
	if !plan.LastError.IsNull() && !plan.LastError.IsUnknown() {
		payload["last_error"] = plan.LastError.ValueString()
	}

	if !plan.ConfigJSON.IsNull() && !plan.ConfigJSON.IsUnknown() && strings.TrimSpace(plan.ConfigJSON.ValueString()) != "" {
		cfg, err := tfhelpers.ParseJSONObject(plan.ConfigJSON.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("config_json"), "Invalid JSON", err.Error())
			return browserProviderModel{}, false
		}
		payload["config"] = cfg
	} else if !prior.ConfigJSON.IsNull() && !prior.ConfigJSON.IsUnknown() && strings.TrimSpace(prior.ConfigJSON.ValueString()) != "" {
		cfg, err := tfhelpers.ParseJSONObject(prior.ConfigJSON.ValueString())
		if err == nil {
			payload["config"] = cfg
		}
	}

	row, err := r.client.UpsertBrowserProvider(ctx, payload)
	if err != nil {
		diags.AddError("Error upserting browser provider", err.Error())
		return browserProviderModel{}, false
	}
	return flattenBrowserProvider(row, plan, r.tenantID), true
}

func flattenBrowserProvider(row map[string]any, current browserProviderModel, tenantID string) browserProviderModel {
	next := current
	next.ID = types.StringValue(tfhelpers.GetString(row, "provider"))
	next.TenantID = types.StringValue(tenantID)
	next.ProviderName = types.StringValue(tfhelpers.GetString(row, "provider"))
	next.Name = nullableString(row, "name")
	next.Enabled = types.BoolValue(tfhelpers.GetBool(row, "enabled"))
	next.Status = nullableString(row, "status")
	if raw := row["config"]; raw != nil {
		next.ConfigJSON = types.StringValue(tfhelpers.ToJSONString(raw))
	}
	next.LastError = nullableString(row, "last_error")
	next.CreatedAt = nullableString(row, "created_at")
	next.UpdatedAt = nullableString(row, "updated_at")
	return next
}
