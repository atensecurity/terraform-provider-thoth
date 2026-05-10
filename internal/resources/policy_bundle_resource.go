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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &policyBundleResource{}
var _ resource.ResourceWithImportState = &policyBundleResource{}

type policyBundleResource struct {
	client   *client.Client
	tenantID string
}

type policyBundleResourceModel struct {
	ID              types.String `tfsdk:"id"`
	TenantID        types.String `tfsdk:"tenant_id"`
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	Framework       types.String `tfsdk:"framework"`
	RawPolicy       types.String `tfsdk:"raw_policy"`
	SourceURI       types.String `tfsdk:"source_uri"`
	S3URI           types.String `tfsdk:"s3_uri"`
	S3VersionID     types.String `tfsdk:"s3_version_id"`
	ExpectedHash    types.String `tfsdk:"expected_hash"`
	Assignments     types.Set    `tfsdk:"assignments"`
	Status          types.String `tfsdk:"status"`
	EnforcementMode types.String `tfsdk:"enforcement_mode"`

	Version         types.Int64  `tfsdk:"version"`
	PolicyHash      types.String `tfsdk:"policy_hash"`
	ResolvedVersion types.String `tfsdk:"resolved_version"`
	CreatedBy       types.String `tfsdk:"created_by"`
	CreatedAt       types.String `tfsdk:"created_at"`
	UpdatedAt       types.String `tfsdk:"updated_at"`
}

func NewPolicyBundleResource() resource.Resource {
	return &policyBundleResource{}
}

func (r *policyBundleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_bundle"
}

func (r *policyBundleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages versioned OPA/Cedar policy bundles for runtime sidecar enforcement.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Policy bundle ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant_id": schema.StringAttribute{
				Computed:    true,
				Description: "Tenant ID from provider configuration.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Stable bundle name. Updates create a new version for the same name.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Optional policy bundle description.",
			},
			"framework": schema.StringAttribute{
				Required:    true,
				Description: "Policy framework: OPA or CEDAR.",
				Validators: []validator.String{
					stringvalidator.OneOf("OPA", "CEDAR", "opa", "cedar"),
				},
			},
			"raw_policy": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Raw Rego/Cedar policy payload. Set this or source_uri/s3_uri.",
			},
			"source_uri": schema.StringAttribute{
				Optional:    true,
				Description: "Unified policy source URI (file:// or s3://). Set this or raw_policy.",
			},
			"s3_uri": schema.StringAttribute{
				Optional:    true,
				Description: "Legacy S3 source URI (for example: s3://bucket/path/policy.rego). Set this or raw_policy. Prefer source_uri.",
			},
			"s3_version_id": schema.StringAttribute{
				Optional:    true,
				Description: "Optional S3 object version ID to pin deterministic policy enforcement.",
			},
			"expected_hash": schema.StringAttribute{
				Optional:    true,
				Description: "Optional expected SHA-256 hash (hex or sha256:<hex>) to enforce policy integrity.",
			},
			"assignments": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Assignment targets (for example: all, agent:security-analyst-agent, coding-agent). Defaults to all.",
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			"status": schema.StringAttribute{
				Optional:    true,
				Description: "Bundle lifecycle status: active, staged, paused, or disabled (alias of paused).",
				Validators: []validator.String{
					stringvalidator.OneOf("active", "staged", "paused", "disabled"),
				},
			},
			"enforcement_mode": schema.StringAttribute{
				Optional:    true,
				Description: "Customer-facing policy mode: enforce or observe. Defaults to enforce.",
				Validators: []validator.String{
					stringvalidator.OneOf("enforce", "observe"),
				},
			},
			"version": schema.Int64Attribute{
				Computed:    true,
				Description: "Monotonic policy bundle version.",
			},
			"policy_hash": schema.StringAttribute{
				Computed:    true,
				Description: "SHA-256 hash of policy content.",
			},
			"resolved_version": schema.StringAttribute{
				Computed:    true,
				Description: "Resolved immutable source version (S3 version ID or file revision hint).",
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "Creator identity.",
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

func (r *policyBundleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *policyBundleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyBundleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, err := r.createBundleFromPlan(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error creating policy bundle", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policyBundleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyBundleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	bundleID := strings.TrimSpace(state.ID.ValueString())
	if bundleID == "" {
		resp.State.RemoveResource(ctx)
		return
	}
	row, err := r.client.GetPolicyBundle(ctx, bundleID)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy bundle", err.Error())
		return
	}

	next := flattenPolicyBundle(ctx, row, state, r.tenantID, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policyBundleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policyBundleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, err := r.createBundleFromPlan(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error updating policy bundle", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policyBundleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyBundleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	bundleID := strings.TrimSpace(state.ID.ValueString())
	if bundleID == "" {
		return
	}
	err := r.client.DeletePolicyBundle(ctx, bundleID)
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Error deleting policy bundle", err.Error())
	}
}

func (r *policyBundleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	bundleID := strings.TrimSpace(req.ID)
	if bundleID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use policy bundle ID as import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), bundleID)...)
}

func (r *policyBundleResource) createBundleFromPlan(
	ctx context.Context,
	plan policyBundleResourceModel,
) (policyBundleResourceModel, error) {
	assignments := []string{}
	diags := plan.Assignments.ElementsAs(ctx, &assignments, false)
	if diags.HasError() {
		return policyBundleResourceModel{}, fmt.Errorf("invalid assignments set")
	}
	framework := canonicalizePolicyBundleFramework(plan.Framework.ValueString())
	if framework == "" {
		return policyBundleResourceModel{}, fmt.Errorf("framework must be one of OPA or CEDAR")
	}
	rawPolicy := strings.TrimSpace(plan.RawPolicy.ValueString())
	sourceURI := strings.TrimSpace(plan.SourceURI.ValueString())
	s3URI := strings.TrimSpace(plan.S3URI.ValueString())
	if rawPolicy == "" && sourceURI == "" && s3URI == "" {
		return policyBundleResourceModel{}, fmt.Errorf("set one of raw_policy or source_uri (or legacy s3_uri)")
	}
	if rawPolicy != "" && (sourceURI != "" || s3URI != "") {
		return policyBundleResourceModel{}, fmt.Errorf("set either raw_policy or source_uri/s3_uri, not both")
	}
	if sourceURI != "" && s3URI != "" {
		return policyBundleResourceModel{}, fmt.Errorf("set either source_uri or s3_uri, not both")
	}
	payload := map[string]any{
		"name":        strings.TrimSpace(plan.Name.ValueString()),
		"description": strings.TrimSpace(plan.Description.ValueString()),
		"framework":   framework,
		"assignments": assignments,
	}
	if rawPolicy != "" {
		payload["raw_policy"] = rawPolicy
	}
	if sourceURI != "" {
		payload["source_uri"] = sourceURI
	}
	if s3URI != "" {
		payload["s3_uri"] = s3URI
	}
	if version := strings.TrimSpace(plan.S3VersionID.ValueString()); version != "" {
		payload["s3_version_id"] = version
	}
	if expectedHash := strings.TrimSpace(plan.ExpectedHash.ValueString()); expectedHash != "" {
		payload["expected_hash"] = expectedHash
	}

	status := canonicalizePolicyBundleStatus(plan.Status.ValueString())
	mode := canonicalizePolicyBundleMode(plan.EnforcementMode.ValueString())
	if mode != "" {
		mappedStatus := statusForPolicyBundleMode(mode)
		if status != "" && mappedStatus != status {
			return policyBundleResourceModel{}, fmt.Errorf(
				"status %q conflicts with enforcement_mode %q",
				status,
				mode,
			)
		}
		status = mappedStatus
	}
	if status == "" {
		status = "active"
	}
	if mode == "" {
		mode = modeForPolicyBundleStatus(status)
	}
	payload["status"] = status
	payload["enforcement_mode"] = mode

	row, err := r.client.CreatePolicyBundle(ctx, payload, nil)
	if err != nil {
		return policyBundleResourceModel{}, err
	}
	return flattenPolicyBundle(ctx, row, plan, r.tenantID, nil), nil
}

func canonicalizePolicyBundleFramework(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "OPA":
		return "OPA"
	case "CEDAR":
		return "CEDAR"
	default:
		return ""
	}
}

func canonicalizePolicyBundleStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return ""
	case "active":
		return "active"
	case "staged":
		return "staged"
	case "paused", "disabled":
		return "paused"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func canonicalizePolicyBundleMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return ""
	case "enforce":
		return "enforce"
	case "observe":
		return "observe"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func statusForPolicyBundleMode(mode string) string {
	if mode == "observe" {
		return "staged"
	}
	return "active"
}

func modeForPolicyBundleStatus(status string) string {
	switch canonicalizePolicyBundleStatus(status) {
	case "staged", "paused":
		return "observe"
	default:
		return "enforce"
	}
}

func flattenPolicyBundle(
	ctx context.Context,
	row map[string]any,
	current policyBundleResourceModel,
	tenantID string,
	diagnostics *diag.Diagnostics,
) policyBundleResourceModel {
	next := current
	next.ID = nullableString(row, "id")
	next.TenantID = types.StringValue(tenantID)
	next.Name = nullableString(row, "name")
	next.Description = nullableString(row, "description")
	next.Framework = nullableString(row, "framework")
	// Keep sensitive raw_policy material out of read paths when omitted by API.
	rawPolicy := tfhelpers.GetString(row, "raw_policy")
	if strings.TrimSpace(rawPolicy) != "" {
		next.RawPolicy = types.StringValue(rawPolicy)
	}
	next.SourceURI = nullableString(row, "source_uri")
	next.S3URI = nullableString(row, "s3_uri")
	next.S3VersionID = nullableString(row, "s3_version_id")
	next.ExpectedHash = nullableString(row, "expected_hash")
	rawStatus := strings.TrimSpace(tfhelpers.GetString(row, "status"))
	if rawStatus == "" {
		rawStatus = "active"
	}
	next.Status = types.StringValue(canonicalizePolicyBundleStatus(rawStatus))
	rawMode := strings.TrimSpace(tfhelpers.GetString(row, "enforcement_mode"))
	if canonicalizePolicyBundleMode(rawMode) == "" {
		rawMode = modeForPolicyBundleStatus(rawStatus)
	}
	next.EnforcementMode = types.StringValue(canonicalizePolicyBundleMode(rawMode))
	next.Version = types.Int64Value(tfhelpers.GetInt64(row, "version"))
	next.PolicyHash = nullableString(row, "policy_hash")
	next.ResolvedVersion = nullableString(row, "resolved_version")
	next.CreatedBy = nullableString(row, "created_by")
	next.CreatedAt = nullableString(row, "created_at")
	next.UpdatedAt = nullableString(row, "updated_at")

	assignments := tfhelpers.GetStringSlice(row, "assignments")
	setValue, setDiags := types.SetValueFrom(ctx, types.StringType, assignments)
	if diagnostics != nil {
		diagnostics.Append(setDiags...)
	}
	if !setDiags.HasError() {
		next.Assignments = setValue
	}
	return next
}
