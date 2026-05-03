package resources

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &packAssignmentBulkResource{}
var _ resource.ResourceWithImportState = &packAssignmentBulkResource{}

type packAssignmentBulkResource struct {
	client   *client.Client
	tenantID string
}

type packAssignmentBulkModel struct {
	ID                  types.String `tfsdk:"id"`
	TenantID            types.String `tfsdk:"tenant_id"`
	Trigger             types.String `tfsdk:"trigger"`
	PackIDs             types.List   `tfsdk:"pack_ids"`
	AllAgents           types.Bool   `tfsdk:"all_agents"`
	AgentIDs            types.List   `tfsdk:"agent_ids"`
	FleetIDs            types.List   `tfsdk:"fleet_ids"`
	EndpointIDs         types.List   `tfsdk:"endpoint_ids"`
	ApprovalPolicyID    types.String `tfsdk:"approval_policy_id"`
	Environment         types.String `tfsdk:"environment"`
	OverridesByPackJSON types.String `tfsdk:"overrides_by_pack_json"`
	AppliedCount        types.Int64  `tfsdk:"applied_count"`
	FailedCount         types.Int64  `tfsdk:"failed_count"`
	TotalOps            types.Int64  `tfsdk:"total_ops"`
	TargetAgentIDsJSON  types.String `tfsdk:"target_agent_ids_json"`
	ResultsJSON         types.String `tfsdk:"results_json"`
	LastAppliedAt       types.String `tfsdk:"last_applied_at"`
}

func NewPackAssignmentBulkResource() resource.Resource {
	return &packAssignmentBulkResource{}
}

func (r *packAssignmentBulkResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pack_assignment_bulk"
}

func (r *packAssignmentBulkResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Applies one or more compliance packs to all agents or scoped subsets (agent_ids, fleet_ids, endpoint_ids).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "Synthetic execution ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant_id": schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"trigger": schema.StringAttribute{
				Optional: true,
				Description: "Change this value to force a fresh apply run.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"pack_ids": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "Pack IDs to apply in one bulk operation.",
			},
			"all_agents": schema.BoolAttribute{
				Optional:    true,
				Description: "Apply to all known agents for the tenant.",
			},
			"agent_ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Specific agent IDs to target.",
			},
			"fleet_ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Fleet IDs whose agents should receive the selected packs.",
			},
			"endpoint_ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Endpoint IDs whose agents should receive the selected packs.",
			},
			"approval_policy_id": schema.StringAttribute{
				Optional:    true,
				Description: "Approval policy ID for pack application (defaults to 'default').",
			},
			"environment": schema.StringAttribute{
				Optional:    true,
				Description: "Environment: dev or prod.",
				Validators: []validator.String{
					stringvalidator.OneOf("dev", "prod"),
				},
			},
			"overrides_by_pack_json": schema.StringAttribute{
				Optional:    true,
				Description: "JSON map keyed by pack_id with per-pack overrides.",
			},
			"applied_count": schema.Int64Attribute{Computed: true, Description: "Successful apply operations."},
			"failed_count":  schema.Int64Attribute{Computed: true, Description: "Failed apply operations."},
			"total_ops":     schema.Int64Attribute{Computed: true, Description: "Total attempted apply operations."},
			"target_agent_ids_json": schema.StringAttribute{
				Computed:    true,
				Description: "Resolved target agent IDs as JSON array.",
			},
			"results_json": schema.StringAttribute{
				Computed:    true,
				Description: "Raw apply results as JSON array.",
			},
			"last_applied_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the most recent apply operation.",
			},
		},
	}
}

func (r *packAssignmentBulkResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *packAssignmentBulkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan packAssignmentBulkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, ok := r.apply(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *packAssignmentBulkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state packAssignmentBulkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *packAssignmentBulkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan packAssignmentBulkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, ok := r.apply(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *packAssignmentBulkResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No remote delete operation; this resource represents a bulk apply action.
}

func (r *packAssignmentBulkResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importID := strings.TrimSpace(req.ID)
	if importID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use any non-empty identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), importID)...)
}

func (r *packAssignmentBulkResource) apply(ctx context.Context, plan packAssignmentBulkModel, diags *diag.Diagnostics) (packAssignmentBulkModel, bool) {
	packIDs := listStrings(plan.PackIDs, diags, "pack_ids")
	agentIDs := listStrings(plan.AgentIDs, diags, "agent_ids")
	fleetIDs := listStrings(plan.FleetIDs, diags, "fleet_ids")
	endpointIDs := listStrings(plan.EndpointIDs, diags, "endpoint_ids")
	if diags.HasError() {
		return packAssignmentBulkModel{}, false
	}
	if len(packIDs) == 0 {
		diags.AddAttributeError(path.Root("pack_ids"), "Missing pack_ids", "At least one pack_id is required.")
		return packAssignmentBulkModel{}, false
	}

	allAgents := false
	if !plan.AllAgents.IsNull() && !plan.AllAgents.IsUnknown() {
		allAgents = plan.AllAgents.ValueBool()
	}
	if !allAgents && len(agentIDs) == 0 && len(fleetIDs) == 0 && len(endpointIDs) == 0 {
		diags.AddError("Missing target scope", "Set all_agents=true or provide agent_ids, fleet_ids, or endpoint_ids.")
		return packAssignmentBulkModel{}, false
	}

	payload := map[string]any{
		"pack_ids": packIDs,
	}
	if allAgents {
		payload["all_agents"] = true
	}
	if len(agentIDs) > 0 {
		payload["agent_ids"] = agentIDs
	}
	if len(fleetIDs) > 0 {
		payload["fleet_ids"] = fleetIDs
	}
	if len(endpointIDs) > 0 {
		payload["endpoint_ids"] = endpointIDs
	}
	if !plan.ApprovalPolicyID.IsNull() && !plan.ApprovalPolicyID.IsUnknown() {
		if v := strings.TrimSpace(plan.ApprovalPolicyID.ValueString()); v != "" {
			payload["approval_policy_id"] = v
		}
	}
	if !plan.Environment.IsNull() && !plan.Environment.IsUnknown() {
		if v := strings.TrimSpace(plan.Environment.ValueString()); v != "" {
			payload["environment"] = v
		}
	}
	if !plan.OverridesByPackJSON.IsNull() && !plan.OverridesByPackJSON.IsUnknown() {
		raw := strings.TrimSpace(plan.OverridesByPackJSON.ValueString())
		if raw != "" {
			parsed, err := tfhelpers.ParseJSONObject(raw)
			if err != nil {
				diags.AddAttributeError(path.Root("overrides_by_pack_json"), "Invalid JSON", err.Error())
				return packAssignmentBulkModel{}, false
			}
			overrides := make(map[string]map[string]any, len(parsed))
			for packID, value := range parsed {
				if value == nil {
					continue
				}
				typed, ok := value.(map[string]any)
				if !ok {
					diags.AddAttributeError(
						path.Root("overrides_by_pack_json"),
						"Invalid per-pack override",
						fmt.Sprintf("overrides_by_pack_json[%q] must be a JSON object.", packID),
					)
					return packAssignmentBulkModel{}, false
				}
				overrides[packID] = typed
			}
			if len(overrides) > 0 {
				payload["overrides_by_pack"] = overrides
			}
		}
	}

	row, err := r.client.ApplyPacksBulk(ctx, payload)
	if err != nil {
		diags.AddError("Error applying compliance packs in bulk", err.Error())
		return packAssignmentBulkModel{}, false
	}
	next := flattenPackAssignmentBulk(row, plan, r.tenantID)
	if next.ID.IsNull() || next.ID.IsUnknown() || strings.TrimSpace(next.ID.ValueString()) == "" {
		next.ID = types.StringValue(fmt.Sprintf("%s/%d", r.tenantID, time.Now().UTC().Unix()))
	}
	next.LastAppliedAt = types.StringValue(time.Now().UTC().Format(time.RFC3339))
	return next, true
}

func flattenPackAssignmentBulk(row map[string]any, current packAssignmentBulkModel, tenantID string) packAssignmentBulkModel {
	next := current
	next.TenantID = types.StringValue(tenantID)
	next.AppliedCount = types.Int64Value(tfhelpers.GetInt64(row, "applied_count"))
	next.FailedCount = types.Int64Value(tfhelpers.GetInt64(row, "failed_count"))
	next.TotalOps = types.Int64Value(tfhelpers.GetInt64(row, "total_ops"))
	next.TargetAgentIDsJSON = types.StringValue(tfhelpers.ToJSONArrayString(row["target_agent_ids"]))
	next.ResultsJSON = types.StringValue(tfhelpers.ToJSONArrayString(row["results"]))
	return next
}

func listStrings(value types.List, diags *diag.Diagnostics, attr string) []string {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	items := make([]string, 0)
	diags.Append(value.ElementsAs(context.Background(), &items, false)...)
	if diags.HasError() {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
