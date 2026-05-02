package resources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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

var _ resource.Resource = &approvalDecisionResource{}
var _ resource.ResourceWithImportState = &approvalDecisionResource{}

type approvalDecisionResource struct {
	client   *client.Client
	tenantID string
}

type approvalDecisionModel struct {
	ID         types.String `tfsdk:"id"`
	TenantID   types.String `tfsdk:"tenant_id"`
	ApprovalID types.String `tfsdk:"approval_id"`
	Decision   types.String `tfsdk:"decision"`
	ResolvedBy types.String `tfsdk:"resolved_by"`
	Status     types.String `tfsdk:"status"`
	Reason     types.String `tfsdk:"reason"`
}

func NewApprovalDecisionResource() resource.Resource {
	return &approvalDecisionResource{}
}

func (r *approvalDecisionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_approval_decision"
}

func (r *approvalDecisionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Resolves a Thoth approval request (approve or deny).",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, Description: "Resource ID (approval ID).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":   schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"approval_id": schema.StringAttribute{Required: true, Description: "Approval ID to resolve.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"decision": schema.StringAttribute{
				Required:      true,
				Description:   "Decision value: approve or deny.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.OneOf("approve", "deny", "approved", "blocked"),
				},
			},
			"resolved_by": schema.StringAttribute{Computed: true, Description: "Resolver identity returned by GovAPI."},
			"status":      schema.StringAttribute{Computed: true, Description: "Observed approval status from approvals list endpoint."},
			"reason":      schema.StringAttribute{Computed: true, Description: "Observed approval reason."},
		},
	}
}

func (r *approvalDecisionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *approvalDecisionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan approvalDecisionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	approvalID := strings.TrimSpace(plan.ApprovalID.ValueString())
	decision := strings.TrimSpace(plan.Decision.ValueString())
	if approvalID == "" {
		resp.Diagnostics.AddAttributeError(path.Root("approval_id"), "Missing approval_id", "approval_id must be set.")
		return
	}
	if decision == "" {
		resp.Diagnostics.AddAttributeError(path.Root("decision"), "Missing decision", "decision must be set.")
		return
	}

	out, err := r.client.ResolveApproval(ctx, approvalID, decision)
	if err != nil {
		resp.Diagnostics.AddError("Error resolving approval", err.Error())
		return
	}

	next := plan
	next.ID = types.StringValue(approvalID)
	next.ApprovalID = types.StringValue(approvalID)
	next.TenantID = types.StringValue(r.tenantID)
	next.Decision = nullableString(out, "decision")
	next.ResolvedBy = nullableString(out, "resolved_by")

	if row, found, err := r.findApproval(ctx, approvalID); err == nil && found {
		next.Status = nullableString(row, "status")
		next.Reason = nullableString(row, "reason")
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *approvalDecisionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state approvalDecisionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	row, found, err := r.findApproval(ctx, state.ApprovalID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading approval status", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	state.Status = nullableString(row, "status")
	state.Reason = nullableString(row, "reason")
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *approvalDecisionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// All configurable arguments require replacement.
	var plan approvalDecisionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *approvalDecisionResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No delete operation for resolved approvals.
}

func (r *approvalDecisionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	approvalID := strings.TrimSpace(req.ID)
	if approvalID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use approval_id as import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), approvalID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("approval_id"), approvalID)...)
}

func (r *approvalDecisionResource) findApproval(ctx context.Context, approvalID string) (map[string]any, bool, error) {
	rows, err := r.client.ListApprovals(ctx, "")
	if err != nil {
		return nil, false, err
	}
	row, found := tfhelpers.FindByStringField(rows, "approval_id", approvalID)
	return row, found, nil
}
