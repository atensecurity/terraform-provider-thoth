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

var _ resource.Resource = &policyExceptionReviewResource{}
var _ resource.ResourceWithImportState = &policyExceptionReviewResource{}

type policyExceptionReviewResource struct {
	client   *client.Client
	tenantID string
}

type policyExceptionReviewModel struct {
	ID                types.String `tfsdk:"id"`
	TenantID          types.String `tfsdk:"tenant_id"`
	RequestID         types.String `tfsdk:"request_id"`
	ReviewDecision    types.String `tfsdk:"review_decision"`
	ReviewedBy        types.String `tfsdk:"reviewed_by"`
	ReviewNotes       types.String `tfsdk:"review_notes"`
	PolicyChangeJSON  types.String `tfsdk:"policy_change_json"`
	Owner             types.String `tfsdk:"owner"`
	TargetEnvironment types.String `tfsdk:"target_environment"`
	OverrideExpiresAt types.String `tfsdk:"override_expires_at"`
	Status            types.String `tfsdk:"status"`
	AppliedPolicyJSON types.String `tfsdk:"applied_policy_change_json"`
	UpdatedAt         types.String `tfsdk:"updated_at"`
}

func NewPolicyExceptionReviewResource() resource.Resource {
	return &policyExceptionReviewResource{}
}

func (r *policyExceptionReviewResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_exception_review"
}

func (r *policyExceptionReviewResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Submits a review decision for a policy exception request.",
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
				Required:      true,
				Description:   "Policy exception request ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"review_decision": schema.StringAttribute{
				Required:      true,
				Description:   "Review outcome: approve, deny, request_changes, approve_with_modification.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.OneOf("approve", "deny", "request_changes", "approve_with_modification"),
				},
			},
			"reviewed_by": schema.StringAttribute{
				Required:      true,
				Description:   "Reviewer identity.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"review_notes": schema.StringAttribute{
				Optional:      true,
				Description:   "Optional review notes.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"policy_change_json": schema.StringAttribute{
				Optional:      true,
				Description:   "Optional policy change override JSON payload.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"owner": schema.StringAttribute{
				Optional:      true,
				Description:   "Optional owner metadata used when synthesizing policy artifacts.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"target_environment": schema.StringAttribute{
				Optional:      true,
				Description:   "Optional target environment (for example prod or staging).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"override_expires_at": schema.StringAttribute{
				Optional:      true,
				Description:   "Optional runtime override expiration timestamp (RFC3339).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Resulting policy exception status.",
			},
			"applied_policy_change_json": schema.StringAttribute{
				Computed:    true,
				Description: "Policy change metadata present on the reviewed exception.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Updated timestamp after review.",
			},
		},
	}
}

func (r *policyExceptionReviewResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *policyExceptionReviewResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyExceptionReviewModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	requestID := strings.TrimSpace(plan.RequestID.ValueString())
	if requestID == "" {
		resp.Diagnostics.AddAttributeError(path.Root("request_id"), "Missing request_id", "request_id must be set.")
		return
	}

	payload := map[string]any{
		"review_decision": strings.TrimSpace(plan.ReviewDecision.ValueString()),
		"reviewed_by":     strings.TrimSpace(plan.ReviewedBy.ValueString()),
	}
	setOptionalPayloadString(payload, "review_notes", plan.ReviewNotes)
	setOptionalPayloadString(payload, "owner", plan.Owner)
	setOptionalPayloadString(payload, "target_environment", plan.TargetEnvironment)
	setOptionalPayloadString(payload, "override_expires_at", plan.OverrideExpiresAt)

	if !plan.PolicyChangeJSON.IsNull() && !plan.PolicyChangeJSON.IsUnknown() {
		policyChange, err := tfhelpers.ParseJSONObject(plan.PolicyChangeJSON.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("policy_change_json"),
				"Invalid JSON",
				"policy_change_json must be a valid JSON object.",
			)
			return
		}
		payload["policy_change"] = policyChange
	}

	row, err := r.client.ReviewPolicyException(ctx, requestID, payload)
	if err != nil {
		resp.Diagnostics.AddError("Error reviewing policy exception", err.Error())
		return
	}

	next := flattenPolicyExceptionReview(plan, row, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policyExceptionReviewResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyExceptionReviewModel
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
		resp.Diagnostics.AddError("Error reading policy exception review", err.Error())
		return
	}

	next := flattenPolicyExceptionReview(state, row, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policyExceptionReviewResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policyExceptionReviewModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyExceptionReviewResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// Review records are retained for audit; delete removes only Terraform state.
}

func (r *policyExceptionReviewResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	requestID := strings.TrimSpace(req.ID)
	if requestID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use request_id as import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), requestID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("request_id"), requestID)...)
}

func flattenPolicyExceptionReview(
	current policyExceptionReviewModel,
	row map[string]any,
	tenantID string,
) policyExceptionReviewModel {
	next := current
	requestID := strings.TrimSpace(tfhelpers.GetString(row, "request_id"))
	if requestID == "" {
		requestID = strings.TrimSpace(current.RequestID.ValueString())
	}
	next.ID = types.StringValue(requestID)
	next.RequestID = types.StringValue(requestID)
	next.TenantID = types.StringValue(tenantID)
	next.Status = nullableResourceString(row, "status")
	next.UpdatedAt = nullableResourceString(row, "updated_at")
	next.AppliedPolicyJSON = types.StringValue(tfhelpers.ToJSONString(row["policy_change"]))
	return next
}
