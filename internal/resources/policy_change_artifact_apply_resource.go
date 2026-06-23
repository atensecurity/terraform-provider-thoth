package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &policyChangeArtifactApplyResource{}
var _ resource.ResourceWithImportState = &policyChangeArtifactApplyResource{}

type policyChangeArtifactApplyResource struct {
	client   *client.Client
	tenantID string
}

type policyChangeArtifactApplyModel struct {
	ID              types.String `tfsdk:"id"`
	TenantID        types.String `tfsdk:"tenant_id"`
	RequestID       types.String `tfsdk:"request_id"`
	AppliedBy       types.String `tfsdk:"applied_by"`
	ApplyChannel    types.String `tfsdk:"apply_channel"`
	PolicyFormat    types.String `tfsdk:"policy_format"`
	BundleName      types.String `tfsdk:"bundle_name"`
	BundleDesc      types.String `tfsdk:"bundle_description"`
	Assignments     types.List   `tfsdk:"assignments"`
	EnforcementMode types.String `tfsdk:"enforcement_mode"`
	Status          types.String `tfsdk:"status"`
	ArtifactID      types.String `tfsdk:"artifact_id"`
	TargetEnv       types.String `tfsdk:"target_environment"`
	AppliedAt       types.String `tfsdk:"applied_at"`
	OverrideRevoked types.Bool   `tfsdk:"override_revoked"`
	GovapiResource  types.String `tfsdk:"govapi_resource_json"`
	ResponseJSON    types.String `tfsdk:"response_json"`
}

func NewPolicyChangeArtifactApplyResource() resource.Resource {
	return &policyChangeArtifactApplyResource{}
}

func (r *policyChangeArtifactApplyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_change_artifact_apply"
}

func (r *policyChangeArtifactApplyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Applies a generated policy change artifact through an approved apply channel.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Synthetic apply operation ID.",
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
			"applied_by": schema.StringAttribute{
				Required:      true,
				Description:   "Actor applying the artifact.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"apply_channel": schema.StringAttribute{
				Optional:      true,
				Description:   "Apply channel to use. Defaults to govapi.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.OneOf("govapi", "terraform", "pulumi", "thothctl"),
				},
			},
			"policy_format": schema.StringAttribute{
				Optional:      true,
				Description:   "Preferred policy format for apply payload (cedar, rego, yaml).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.OneOf("cedar", "rego", "yaml"),
				},
			},
			"bundle_name": schema.StringAttribute{
				Optional:      true,
				Description:   "Optional override bundle name for govapi apply.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"bundle_description": schema.StringAttribute{
				Optional:      true,
				Description:   "Optional bundle description for govapi apply.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"assignments": schema.ListAttribute{
				Optional:      true,
				ElementType:   types.StringType,
				Description:   "Optional assignment targets for govapi policy bundle apply.",
				PlanModifiers: []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
			"enforcement_mode": schema.StringAttribute{
				Optional:      true,
				Description:   "Optional enforcement mode override (enforce or observe).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"status": schema.StringAttribute{
				Optional:      true,
				Description:   "Optional policy bundle status override (active, staged, paused, disabled).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"artifact_id": schema.StringAttribute{
				Computed:    true,
				Description: "Artifact ID used for apply.",
			},
			"target_environment": schema.StringAttribute{
				Computed:    true,
				Description: "Target environment for the apply operation.",
			},
			"applied_at": schema.StringAttribute{
				Computed:    true,
				Description: "Apply execution timestamp.",
			},
			"override_revoked": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether a temporary runtime override was revoked after apply.",
			},
			"govapi_resource_json": schema.StringAttribute{
				Computed:    true,
				Description: "GovAPI resource returned by apply operation as JSON.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full apply response as JSON.",
			},
		},
	}
}

func (r *policyChangeArtifactApplyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *policyChangeArtifactApplyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyChangeArtifactApplyModel
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
		"applied_by": strings.TrimSpace(plan.AppliedBy.ValueString()),
	}
	if channel := strings.TrimSpace(plan.ApplyChannel.ValueString()); channel != "" {
		payload["apply_channel"] = channel
	} else {
		payload["apply_channel"] = "govapi"
	}
	setOptionalPayloadString(payload, "policy_format", plan.PolicyFormat)
	setOptionalPayloadString(payload, "bundle_name", plan.BundleName)
	setOptionalPayloadString(payload, "bundle_description", plan.BundleDesc)
	setOptionalPayloadString(payload, "enforcement_mode", plan.EnforcementMode)
	setOptionalPayloadString(payload, "status", plan.Status)

	if !plan.Assignments.IsNull() && !plan.Assignments.IsUnknown() {
		assignments := []string{}
		resp.Diagnostics.Append(plan.Assignments.ElementsAs(ctx, &assignments, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		payload["assignments"] = assignments
	}

	row, err := r.client.ApplyPolicyChangeArtifact(ctx, requestID, payload)
	if err != nil {
		resp.Diagnostics.AddError("Error applying policy change artifact", err.Error())
		return
	}

	next := flattenPolicyChangeArtifactApply(plan, row, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policyChangeArtifactApplyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyChangeArtifactApplyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	requestID := strings.TrimSpace(state.RequestID.ValueString())
	if requestID == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	artifact, err := r.client.GetPolicyChangeArtifact(ctx, requestID)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading applied policy change artifact", err.Error())
		return
	}

	if env := strings.TrimSpace(tfhelpers.GetString(artifact, "target_environment")); env != "" {
		state.TargetEnv = types.StringValue(env)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *policyChangeArtifactApplyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policyChangeArtifactApplyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyChangeArtifactApplyResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// Apply is an auditable action; deleting only removes Terraform state.
}

func (r *policyChangeArtifactApplyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	requestID := strings.TrimSpace(req.ID)
	if requestID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use request_id as import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), requestID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("request_id"), requestID)...)
}

func flattenPolicyChangeArtifactApply(
	current policyChangeArtifactApplyModel,
	row map[string]any,
	tenantID string,
) policyChangeArtifactApplyModel {
	next := current
	requestID := strings.TrimSpace(tfhelpers.GetString(row, "request_id"))
	if requestID == "" {
		requestID = strings.TrimSpace(current.RequestID.ValueString())
	}
	next.ID = types.StringValue(fmt.Sprintf("%s/%s", requestID, strings.TrimSpace(tfhelpers.GetString(row, "applied_at"))))
	next.RequestID = types.StringValue(requestID)
	next.TenantID = types.StringValue(tenantID)
	if v := strings.TrimSpace(tfhelpers.GetString(row, "apply_channel")); v != "" {
		next.ApplyChannel = types.StringValue(v)
	}
	if v := strings.TrimSpace(tfhelpers.GetString(row, "policy_format")); v != "" {
		next.PolicyFormat = types.StringValue(v)
	}
	next.ArtifactID = nullableResourceString(row, "artifact_id")
	next.TargetEnv = nullableResourceString(row, "target_environment")
	next.AppliedAt = nullableResourceString(row, "applied_at")
	next.OverrideRevoked = types.BoolValue(tfhelpers.GetBool(row, "override_revoked"))
	next.GovapiResource = types.StringValue(tfhelpers.ToJSONString(row["govapi_resource"]))
	next.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(row))
	return next
}
