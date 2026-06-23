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

var _ resource.Resource = &policyExceptionResource{}
var _ resource.ResourceWithImportState = &policyExceptionResource{}

type policyExceptionResource struct {
	client   *client.Client
	tenantID string
}

type policyExceptionResourceModel struct {
	ID                    types.String `tfsdk:"id"`
	TenantID              types.String `tfsdk:"tenant_id"`
	RequestID             types.String `tfsdk:"request_id"`
	ViolationID           types.String `tfsdk:"violation_id"`
	HoldToken             types.String `tfsdk:"hold_token"`
	AgentID               types.String `tfsdk:"agent_id"`
	ToolName              types.String `tfsdk:"tool_name"`
	RequestedBy           types.String `tfsdk:"requested_by"`
	BusinessJustification types.String `tfsdk:"business_justification"`
	FrequencyEstimate     types.String `tfsdk:"frequency_estimate"`
	DataSensitivity       types.String `tfsdk:"data_sensitivity"`
	Alternatives          types.String `tfsdk:"alternatives_considered"`
	Status                types.String `tfsdk:"status"`
	ReviewedBy            types.String `tfsdk:"reviewed_by"`
	ReviewDecision        types.String `tfsdk:"review_decision"`
	ReviewNotes           types.String `tfsdk:"review_notes"`
	PolicyChangeJSON      types.String `tfsdk:"policy_change_json"`
	CreatedAt             types.String `tfsdk:"created_at"`
	UpdatedAt             types.String `tfsdk:"updated_at"`
}

func NewPolicyExceptionResource() resource.Resource {
	return &policyExceptionResource{}
}

func (r *policyExceptionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_exception"
}

func (r *policyExceptionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Creates and reads a policy exception request.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Resource ID (request ID).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant_id": schema.StringAttribute{
				Computed:    true,
				Description: "Tenant ID from provider configuration.",
			},
			"request_id": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "Optional request ID. If omitted, enforcer generates one.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"violation_id": schema.StringAttribute{
				Required:      true,
				Description:   "Violation ID associated with this exception request.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"hold_token": schema.StringAttribute{
				Optional:      true,
				Description:   "Optional hold token when exception is tied to STEP_UP workflow.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"agent_id": schema.StringAttribute{
				Optional:      true,
				Description:   "Agent ID associated with the request.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"tool_name": schema.StringAttribute{
				Optional:      true,
				Description:   "Tool/action name associated with the request.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"requested_by": schema.StringAttribute{
				Required:      true,
				Description:   "Requester identity.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"business_justification": schema.StringAttribute{
				Required:      true,
				Description:   "Business reason for requesting the exception.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"frequency_estimate": schema.StringAttribute{
				Required:      true,
				Description:   "How often this exception is expected to occur.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"data_sensitivity": schema.StringAttribute{
				Required:      true,
				Description:   "Data sensitivity level touched by this exception.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"alternatives_considered": schema.StringAttribute{
				Optional:      true,
				Description:   "Optional alternatives reviewed before requesting an exception.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Current policy exception status.",
			},
			"reviewed_by": schema.StringAttribute{
				Computed:    true,
				Description: "Reviewer identity when present.",
			},
			"review_decision": schema.StringAttribute{
				Computed:    true,
				Description: "Review decision when present.",
			},
			"review_notes": schema.StringAttribute{
				Computed:    true,
				Description: "Review notes when present.",
			},
			"policy_change_json": schema.StringAttribute{
				Computed:    true,
				Description: "Policy change metadata returned by the review flow.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Creation timestamp.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Last update timestamp.",
			},
		},
	}
}

func (r *policyExceptionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *policyExceptionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyExceptionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := map[string]any{
		"violation_id":           strings.TrimSpace(plan.ViolationID.ValueString()),
		"requested_by":           strings.TrimSpace(plan.RequestedBy.ValueString()),
		"business_justification": strings.TrimSpace(plan.BusinessJustification.ValueString()),
		"frequency_estimate":     strings.TrimSpace(plan.FrequencyEstimate.ValueString()),
		"data_sensitivity":       strings.TrimSpace(plan.DataSensitivity.ValueString()),
	}
	setOptionalPayloadString(payload, "request_id", plan.RequestID)
	setOptionalPayloadString(payload, "hold_token", plan.HoldToken)
	setOptionalPayloadString(payload, "agent_id", plan.AgentID)
	setOptionalPayloadString(payload, "tool_name", plan.ToolName)
	setOptionalPayloadString(payload, "alternatives_considered", plan.Alternatives)

	row, err := r.client.CreatePolicyException(ctx, payload)
	if err != nil {
		resp.Diagnostics.AddError("Error creating policy exception", err.Error())
		return
	}

	next := flattenPolicyException(plan, row, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policyExceptionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyExceptionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	requestID := strings.TrimSpace(state.RequestID.ValueString())
	if requestID == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	row, err := r.client.GetPolicyException(ctx, requestID)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy exception", err.Error())
		return
	}

	next := flattenPolicyException(state, row, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policyExceptionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policyExceptionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyExceptionResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// Policy exception records are immutable audit artifacts; deleting only removes Terraform state.
}

func (r *policyExceptionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	requestID := strings.TrimSpace(req.ID)
	if requestID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use request_id as import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), requestID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("request_id"), requestID)...)
}

func flattenPolicyException(
	current policyExceptionResourceModel,
	row map[string]any,
	tenantID string,
) policyExceptionResourceModel {
	next := current
	requestID := strings.TrimSpace(tfhelpers.GetString(row, "request_id"))
	if requestID == "" {
		requestID = strings.TrimSpace(current.RequestID.ValueString())
	}
	next.ID = types.StringValue(requestID)
	next.RequestID = types.StringValue(requestID)
	next.TenantID = types.StringValue(tenantID)
	next.ViolationID = nullableResourceString(row, "violation_id")
	next.HoldToken = nullableResourceString(row, "hold_token")
	next.AgentID = nullableResourceString(row, "agent_id")
	next.ToolName = nullableResourceString(row, "tool_name")
	next.RequestedBy = nullableResourceString(row, "requested_by")
	next.BusinessJustification = nullableResourceString(row, "business_justification")
	next.FrequencyEstimate = nullableResourceString(row, "frequency_estimate")
	next.DataSensitivity = nullableResourceString(row, "data_sensitivity")
	next.Alternatives = nullableResourceString(row, "alternatives_considered")
	next.Status = nullableResourceString(row, "status")
	next.ReviewedBy = nullableResourceString(row, "reviewed_by")
	next.ReviewDecision = nullableResourceString(row, "review_decision")
	next.ReviewNotes = nullableResourceString(row, "review_notes")
	next.PolicyChangeJSON = types.StringValue(tfhelpers.ToJSONString(row["policy_change"]))
	next.CreatedAt = nullableResourceString(row, "created_at")
	next.UpdatedAt = nullableResourceString(row, "updated_at")
	return next
}

func nullableResourceString(m map[string]any, key string) types.String {
	v := strings.TrimSpace(tfhelpers.GetString(m, key))
	if v == "" {
		return types.StringNull()
	}
	return types.StringValue(v)
}

func setOptionalPayloadString(target map[string]any, key string, value types.String) {
	if value.IsNull() || value.IsUnknown() {
		return
	}
	if trimmed := strings.TrimSpace(value.ValueString()); trimmed != "" {
		target[key] = trimmed
	}
}
