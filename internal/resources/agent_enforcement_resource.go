package resources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

// Every default policy enforces, so destroying the resource returns there.
const (
	agentEnforcementDefaultMode     = "enforce"
	agentEnforcementDefaultHighRisk = "hold"
	// A person declining a held action raises the agent's same-kind actions
	// for 30 minutes unless the agent is set stronger.
	agentEnforcementDefaultAfterDecline = "raise"
	agentEnforcementDefaultMinutes      = 30
)

var _ resource.Resource = &agentEnforcementResource{}
var _ resource.ResourceWithImportState = &agentEnforcementResource{}

type agentEnforcementResource struct {
	client *client.Client
}

type agentEnforcementModel struct {
	ID              types.String `tfsdk:"id"`
	AgentID         types.String `tfsdk:"agent_id"`
	EnforcementMode types.String `tfsdk:"enforcement_mode"`
	HighRiskAction  types.String `tfsdk:"high_risk_action"`
	AfterDecline    types.String `tfsdk:"after_decline"`
	AfterDeclineMin types.Int64  `tfsdk:"after_decline_minutes"`
}

func NewAgentEnforcementResource() resource.Resource {
	return &agentEnforcementResource{}
}

func (r *agentEnforcementResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent_enforcement"
}

func (r *agentEnforcementResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An agent's enforcement mode. In `observe` Thoth evaluates every action, records what enforcing " +
			"would have decided (see the agent's observe summary) and allows it; in `enforce` decisions apply. " +
			"Destroying this resource returns the agent to `enforce`, which is what every default policy does.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Terraform resource identifier (agent ID).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"agent_id": schema.StringAttribute{
				Required:      true,
				Description:   "The registered agent.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"enforcement_mode": schema.StringAttribute{
				Required:    true,
				Description: "`observe` (evaluate and record, allow everything) or `enforce` (decisions apply).",
				Validators:  []validator.String{stringvalidator.OneOf("observe", "enforce")},
			},
			"high_risk_action": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(agentEnforcementDefaultHighRisk),
				Description: "While enforcing, what a high model risk score does: `hold` the action for approval (default) " +
					"or `deny` it. Rules decide either way; a score can only make a decision stricter.",
				Validators: []validator.String{stringvalidator.OneOf("hold", "deny")},
			},
			"after_decline": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(agentEnforcementDefaultAfterDecline),
				Description: "What a person declining one of this agent's held actions does. `raise` (default): its next " +
					"actions of the same kind need approval for `after_decline_minutes`, in every session. `stop`: the " +
					"session the declined action was in is isolated until a person releases it. `quarantine`: the agent " +
					"is quarantined. A policy deny quarantines the agent whatever this says.",
				Validators: []validator.String{stringvalidator.OneOf("raise", "stop", "quarantine")},
			},
			"after_decline_minutes": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(agentEnforcementDefaultMinutes),
				Description: "With `after_decline` set to `raise`, how long the agent's same-kind actions need approval: 5 to 1440 minutes (default 30). Ignored for `stop` and `quarantine`.",
				Validators:  []validator.Int64{int64validator.Between(5, 1440)},
			},
		},
	}
}

func (r *agentEnforcementResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if data := tfhelpers.RequireResourceClient(req, resp); data != nil {
		r.client = data.Client
	}
}

func (r *agentEnforcementResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan agentEnforcementModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.apply(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error setting agent enforcement", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *agentEnforcementResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state agentEnforcementModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetAgentEnforcement(ctx, state.AgentID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading agent enforcement", err.Error())
		return
	}
	next := flattenAgentEnforcement(out, state.AgentID.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *agentEnforcementResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan agentEnforcementModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.apply(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error updating agent enforcement", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *agentEnforcementResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state agentEnforcementModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.UpdateAgentEnforcement(ctx, state.AgentID.ValueString(), agentEnforcementDefaultMode, agentEnforcementDefaultHighRisk, agentEnforcementDefaultAfterDecline, agentEnforcementDefaultMinutes)
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Error returning the agent to enforce", err.Error())
	}
}

func (r *agentEnforcementResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	agentID := strings.TrimSpace(req.ID)
	if agentID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use the agent ID as the import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), agentID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("agent_id"), agentID)...)
}

func (r *agentEnforcementResource) apply(ctx context.Context, plan agentEnforcementModel) (agentEnforcementModel, error) {
	out, err := r.client.UpdateAgentEnforcement(ctx, plan.AgentID.ValueString(), plan.EnforcementMode.ValueString(), plan.HighRiskAction.ValueString(), plan.AfterDecline.ValueString(), plan.AfterDeclineMin.ValueInt64())
	if err != nil {
		return agentEnforcementModel{}, err
	}
	next := flattenAgentEnforcement(out, plan.AgentID.ValueString())
	// Minutes apply to raise only; keep the configured value for the others,
	// so a plan doesn't show a change the server never stores.
	if next.AfterDecline.ValueString() != "raise" {
		next.AfterDeclineMin = plan.AfterDeclineMin
	}
	return next, nil
}

func flattenAgentEnforcement(out map[string]any, agentID string) agentEnforcementModel {
	mode := tfhelpers.GetString(out, "enforcement_mode")
	if mode == "" {
		mode = agentEnforcementDefaultMode
	}
	highRisk := tfhelpers.GetString(out, "high_risk_action")
	if highRisk == "" {
		highRisk = agentEnforcementDefaultHighRisk
	}
	afterDecline := tfhelpers.GetString(out, "after_decline")
	if afterDecline == "" {
		afterDecline = agentEnforcementDefaultAfterDecline
	}
	minutes := int64(agentEnforcementDefaultMinutes)
	if value, ok := out["after_decline_minutes"].(float64); ok && value > 0 {
		minutes = int64(value)
	}
	return agentEnforcementModel{
		ID:              types.StringValue(agentID),
		AgentID:         types.StringValue(agentID),
		EnforcementMode: types.StringValue(mode),
		HighRiskAction:  types.StringValue(highRisk),
		AfterDecline:    types.StringValue(afterDecline),
		AfterDeclineMin: types.Int64Value(minutes),
	}
}
