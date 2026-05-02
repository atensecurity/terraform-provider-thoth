package resources

import (
	"context"
	"fmt"
	"strings"

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

var _ resource.Resource = &packAssignmentResource{}
var _ resource.ResourceWithImportState = &packAssignmentResource{}

type packAssignmentResource struct {
	client   *client.Client
	tenantID string
}

type packAssignmentModel struct {
	ID               types.String `tfsdk:"id"`
	TenantID         types.String `tfsdk:"tenant_id"`
	AgentID          types.String `tfsdk:"agent_id"`
	PackID           types.String `tfsdk:"pack_id"`
	ApprovalPolicyID types.String `tfsdk:"approval_policy_id"`
	Environment      types.String `tfsdk:"environment"`
	OverridesJSON    types.String `tfsdk:"overrides_json"`
	Status           types.String `tfsdk:"status"`
	Regulation       types.String `tfsdk:"regulation"`
	RuleVersion      types.Int64  `tfsdk:"rule_version"`
	AppliedBy        types.String `tfsdk:"applied_by"`
	AppliedAt        types.String `tfsdk:"applied_at"`
	RevokedAt        types.String `tfsdk:"revoked_at"`
}

func NewPackAssignmentResource() resource.Resource {
	return &packAssignmentResource{}
}

func (r *packAssignmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pack_assignment"
}

func (r *packAssignmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Applies a compliance pack to a specific agent and tracks assignment state.",
		Attributes: map[string]schema.Attribute{
			"id":                 schema.StringAttribute{Computed: true, Description: "Resource ID (agent_id/pack_id).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":          schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"agent_id":           schema.StringAttribute{Required: true, Description: "Target agent ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"pack_id":            schema.StringAttribute{Required: true, Description: "Compliance pack identifier.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"approval_policy_id": schema.StringAttribute{Optional: true, Description: "Approval policy ID for pack application."},
			"environment": schema.StringAttribute{
				Optional:    true,
				Description: "Environment: dev or prod.",
				Validators: []validator.String{
					stringvalidator.OneOf("dev", "prod"),
				},
			},
			"overrides_json": schema.StringAttribute{Optional: true, Description: "Pack override JSON object."},
			"status":         schema.StringAttribute{Computed: true, Description: "Current assignment status."},
			"regulation":     schema.StringAttribute{Computed: true, Description: "Regulation family for applied pack."},
			"rule_version":   schema.Int64Attribute{Computed: true, Description: "Rule version applied by enforcer."},
			"applied_by":     schema.StringAttribute{Computed: true, Description: "Principal that applied the pack."},
			"applied_at":     schema.StringAttribute{Computed: true, Description: "Apply timestamp."},
			"revoked_at":     schema.StringAttribute{Computed: true, Description: "Revoke timestamp when assignment is removed."},
		},
	}
}

func (r *packAssignmentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *packAssignmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan packAssignmentModel
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

func (r *packAssignmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state packAssignmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	row, found, err := r.findAgentPack(ctx, state.AgentID.ValueString(), state.PackID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading pack assignment", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	next := flattenPackAssignment(row, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *packAssignmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan packAssignmentModel
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

func (r *packAssignmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state packAssignmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.RevokePackFromAgent(ctx, state.AgentID.ValueString(), state.PackID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Error revoking pack assignment", err.Error())
	}
}

func (r *packAssignmentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(strings.TrimSpace(req.ID), "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use import format: agent_id/pack_id")
		return
	}
	agentID := strings.TrimSpace(parts[0])
	packID := strings.TrimSpace(parts[1])
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), fmt.Sprintf("%s/%s", agentID, packID))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("agent_id"), agentID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("pack_id"), packID)...)
}

func (r *packAssignmentResource) apply(ctx context.Context, plan packAssignmentModel, diags *diag.Diagnostics) (packAssignmentModel, bool) {
	agentID := strings.TrimSpace(plan.AgentID.ValueString())
	packID := strings.TrimSpace(plan.PackID.ValueString())
	if agentID == "" {
		diags.AddAttributeError(path.Root("agent_id"), "Missing agent_id", "agent_id must be set.")
		return packAssignmentModel{}, false
	}
	if packID == "" {
		diags.AddAttributeError(path.Root("pack_id"), "Missing pack_id", "pack_id must be set.")
		return packAssignmentModel{}, false
	}

	payload := map[string]any{"pack_id": packID}
	if !plan.ApprovalPolicyID.IsNull() && !plan.ApprovalPolicyID.IsUnknown() {
		payload["approval_policy_id"] = plan.ApprovalPolicyID.ValueString()
	}
	if !plan.Environment.IsNull() && !plan.Environment.IsUnknown() {
		payload["environment"] = plan.Environment.ValueString()
	}
	if !plan.OverridesJSON.IsNull() && !plan.OverridesJSON.IsUnknown() && strings.TrimSpace(plan.OverridesJSON.ValueString()) != "" {
		overrides, err := tfhelpers.ParseJSONObject(plan.OverridesJSON.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("overrides_json"), "Invalid JSON", err.Error())
			return packAssignmentModel{}, false
		}
		payload["overrides"] = overrides
	}

	row, err := r.client.ApplyPackToAgent(ctx, agentID, payload)
	if err != nil {
		diags.AddError("Error applying compliance pack", err.Error())
		return packAssignmentModel{}, false
	}
	next := flattenPackAssignment(row, plan, r.tenantID)
	next.ID = types.StringValue(fmt.Sprintf("%s/%s", agentID, packID))
	next.AgentID = types.StringValue(agentID)
	next.PackID = types.StringValue(packID)
	return next, true
}

func (r *packAssignmentResource) findAgentPack(ctx context.Context, agentID, packID string) (map[string]any, bool, error) {
	rows, err := r.client.ListAgentPacks(ctx, agentID)
	if err != nil {
		return nil, false, err
	}
	row, found := tfhelpers.FindByStringField(rows, "pack_id", packID)
	return row, found, nil
}

func flattenPackAssignment(row map[string]any, current packAssignmentModel, tenantID string) packAssignmentModel {
	next := current
	next.TenantID = types.StringValue(tenantID)
	next.Status = nullableString(row, "status")
	next.Regulation = nullableString(row, "regulation")
	next.RuleVersion = types.Int64Value(tfhelpers.GetInt64(row, "rule_version"))
	next.AppliedBy = nullableString(row, "applied_by")
	next.AppliedAt = nullableString(row, "applied_at")
	next.RevokedAt = nullableString(row, "revoked_at")
	return next
}
