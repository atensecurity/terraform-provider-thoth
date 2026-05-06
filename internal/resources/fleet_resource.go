package resources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &fleetResource{}
var _ resource.ResourceWithImportState = &fleetResource{}

type fleetResource struct {
	client   *client.Client
	tenantID string
}

type fleetResourceModel struct {
	ID                  types.String  `tfsdk:"id"`
	FleetID             types.String  `tfsdk:"fleet_id"`
	TenantID            types.String  `tfsdk:"tenant_id"`
	Name                types.String  `tfsdk:"name"`
	FleetCode           types.String  `tfsdk:"fleet_code"`
	Region              types.String  `tfsdk:"region"`
	PolicyID            types.String  `tfsdk:"policy_id"`
	PolicyName          types.String  `tfsdk:"policy_name"`
	Status              types.String  `tfsdk:"status"`
	RolloutStrategy     types.String  `tfsdk:"rollout_strategy"`
	RolloutPct          types.Int64   `tfsdk:"rollout_pct"`
	DriftPct            types.Float64 `tfsdk:"drift_pct"`
	DriftedEndpoints    types.Int64   `tfsdk:"drifted_endpoint_count"`
	EndpointCount       types.Int64   `tfsdk:"endpoint_count"`
	CompliancePct       types.Float64 `tfsdk:"compliance_pct"`
	Provider            types.String  `tfsdk:"provider"`
	LastDeployedAt      types.String  `tfsdk:"last_deployed_at"`
	LastDeployedVersion types.String  `tfsdk:"last_deployed_version"`
	CreatedAt           types.String  `tfsdk:"created_at"`
	UpdatedAt           types.String  `tfsdk:"updated_at"`
}

func NewFleetResource() resource.Resource {
	return &fleetResource{}
}

func (r *fleetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fleet"
}

func (r *fleetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages tenant fleets and lifecycle metadata.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource ID (fleet_id).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"fleet_id":               schema.StringAttribute{Computed: true, Description: "Fleet identifier."},
			"tenant_id":              schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"name":                   schema.StringAttribute{Required: true, Description: "Fleet display name."},
			"fleet_code":             schema.StringAttribute{Computed: true, Description: "Fleet code."},
			"region":                 schema.StringAttribute{Optional: true, Description: "Fleet region."},
			"policy_id":              schema.StringAttribute{Optional: true, Description: "Attached policy ID."},
			"policy_name":            schema.StringAttribute{Optional: true, Description: "Attached policy name."},
			"status":                 schema.StringAttribute{Optional: true, Description: "Fleet status (active, paused, deploying, error)."},
			"rollout_strategy":       schema.StringAttribute{Optional: true, Description: "Rollout strategy (canary or staged)."},
			"rollout_pct":            schema.Int64Attribute{Optional: true, Description: "Current rollout percentage."},
			"drift_pct":              schema.Float64Attribute{Computed: true, Description: "Percent drift detected."},
			"drifted_endpoint_count": schema.Int64Attribute{Computed: true, Description: "Drifted endpoint count."},
			"endpoint_count":         schema.Int64Attribute{Computed: true, Description: "Endpoint count in this fleet."},
			"compliance_pct":         schema.Float64Attribute{Computed: true, Description: "Compliance percentage."},
			"provider":               schema.StringAttribute{Optional: true, Description: "Provider hint (jamf, intune, workspace_one, custom, none)."},
			"last_deployed_at":       schema.StringAttribute{Computed: true, Description: "Last deployment timestamp."},
			"last_deployed_version":  schema.StringAttribute{Computed: true, Description: "Last deployed version."},
			"created_at":             schema.StringAttribute{Computed: true, Description: "Creation timestamp."},
			"updated_at":             schema.StringAttribute{Computed: true, Description: "Last update timestamp."},
		},
	}
}

func (r *fleetResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *fleetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan fleetResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := r.fleetPayload(plan)
	created, err := r.client.CreateFleet(ctx, payload)
	if err != nil {
		resp.Diagnostics.AddError("Error creating fleet", err.Error())
		return
	}

	fleetID := strings.TrimSpace(tfhelpers.GetString(created, "fleet_id"))
	if fleetID == "" {
		resp.Diagnostics.AddError("Error creating fleet", "GovAPI did not return fleet_id.")
		return
	}

	row, err := r.client.GetFleet(ctx, fleetID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading fleet after create", err.Error())
		return
	}

	next := flattenFleet(row, plan, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *fleetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state fleetResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	fleetID := strings.TrimSpace(state.FleetID.ValueString())
	if fleetID == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	row, err := r.client.GetFleet(ctx, fleetID)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading fleet", err.Error())
		return
	}

	next := flattenFleet(row, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *fleetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan fleetResourceModel
	var state fleetResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	fleetID := strings.TrimSpace(state.FleetID.ValueString())
	if fleetID == "" {
		resp.Diagnostics.AddError("Missing fleet_id", "Cannot update fleet without fleet_id in state.")
		return
	}

	updates := r.fleetPayload(plan)
	if _, err := r.client.UpdateFleet(ctx, fleetID, updates); err != nil {
		resp.Diagnostics.AddError("Error updating fleet", err.Error())
		return
	}

	row, err := r.client.GetFleet(ctx, fleetID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading fleet after update", err.Error())
		return
	}

	next := flattenFleet(row, plan, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *fleetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state fleetResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	fleetID := strings.TrimSpace(state.FleetID.ValueString())
	if fleetID == "" {
		return
	}

	if err := r.client.DeleteFleet(ctx, fleetID); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Error deleting fleet", err.Error())
	}
}

func (r *fleetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	fleetID := strings.TrimSpace(req.ID)
	if fleetID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use fleet_id as import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), fleetID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("fleet_id"), fleetID)...)
}

func (r *fleetResource) fleetPayload(plan fleetResourceModel) map[string]any {
	payload := map[string]any{
		"name": strings.TrimSpace(plan.Name.ValueString()),
	}
	if !plan.Region.IsNull() && !plan.Region.IsUnknown() {
		payload["region"] = strings.TrimSpace(plan.Region.ValueString())
	}
	if !plan.PolicyID.IsNull() && !plan.PolicyID.IsUnknown() {
		payload["policy_id"] = strings.TrimSpace(plan.PolicyID.ValueString())
	}
	if !plan.PolicyName.IsNull() && !plan.PolicyName.IsUnknown() {
		payload["policy_name"] = strings.TrimSpace(plan.PolicyName.ValueString())
	}
	if !plan.Status.IsNull() && !plan.Status.IsUnknown() {
		payload["status"] = strings.TrimSpace(plan.Status.ValueString())
	}
	if !plan.RolloutStrategy.IsNull() && !plan.RolloutStrategy.IsUnknown() {
		payload["rollout_strategy"] = strings.TrimSpace(plan.RolloutStrategy.ValueString())
	}
	if !plan.RolloutPct.IsNull() && !plan.RolloutPct.IsUnknown() {
		payload["rollout_pct"] = plan.RolloutPct.ValueInt64()
	}
	if !plan.Provider.IsNull() && !plan.Provider.IsUnknown() {
		payload["provider"] = strings.TrimSpace(plan.Provider.ValueString())
	}
	return payload
}

func flattenFleet(row map[string]any, current fleetResourceModel, tenantID string) fleetResourceModel {
	next := current
	fleetID := strings.TrimSpace(tfhelpers.GetString(row, "fleet_id"))
	next.ID = types.StringValue(fleetID)
	next.FleetID = types.StringValue(fleetID)
	next.TenantID = types.StringValue(tenantID)
	next.Name = nullableString(row, "name")
	next.FleetCode = nullableString(row, "fleet_code")
	next.Region = nullableString(row, "region")
	next.PolicyID = nullableString(row, "policy_id")
	next.PolicyName = nullableString(row, "policy_name")
	next.Status = nullableString(row, "status")
	next.RolloutStrategy = nullableString(row, "rollout_strategy")
	next.RolloutPct = types.Int64Value(tfhelpers.GetInt64(row, "rollout_pct"))
	next.DriftPct = types.Float64Value(tfhelpers.GetFloat64(row, "drift_pct"))
	next.DriftedEndpoints = types.Int64Value(tfhelpers.GetInt64(row, "drifted_endpoint_count"))
	next.EndpointCount = types.Int64Value(tfhelpers.GetInt64(row, "endpoint_count"))
	next.CompliancePct = types.Float64Value(tfhelpers.GetFloat64(row, "compliance_pct"))
	next.Provider = nullableString(row, "provider")
	next.LastDeployedAt = nullableString(row, "last_deployed_at")
	next.LastDeployedVersion = nullableString(row, "last_deployed_version")
	next.CreatedAt = nullableString(row, "created_at")
	next.UpdatedAt = nullableString(row, "updated_at")
	return next
}
