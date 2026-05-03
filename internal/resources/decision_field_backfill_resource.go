package resources

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
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

var _ resource.Resource = &decisionFieldBackfillResource{}
var _ resource.ResourceWithImportState = &decisionFieldBackfillResource{}

type decisionFieldBackfillResource struct {
	client   *client.Client
	tenantID string
}

type decisionFieldBackfillModel struct {
	ID                   types.String `tfsdk:"id"`
	TenantID             types.String `tfsdk:"tenant_id"`
	Trigger              types.String `tfsdk:"trigger"`
	Limit                types.Int64  `tfsdk:"limit"`
	WindowHours          types.Int64  `tfsdk:"window_hours"`
	IncludeBlockedEvents types.Bool   `tfsdk:"include_blocked_events"`
	DryRun               types.Bool   `tfsdk:"dry_run"`

	Examined                  types.Int64  `tfsdk:"examined"`
	Candidates                types.Int64  `tfsdk:"candidates"`
	Updated                   types.Int64  `tfsdk:"updated"`
	WouldUpdate               types.Int64  `tfsdk:"would_update"`
	SkippedNoChange           types.Int64  `tfsdk:"skipped_no_change"`
	PatchedViolationID        types.Int64  `tfsdk:"patched_violation_id"`
	PatchedDecisionReasonCode types.Int64  `tfsdk:"patched_decision_reason_code"`
	PatchedAuthorization      types.Int64  `tfsdk:"patched_authorization_decision"`
	PatchedTraceID            types.Int64  `tfsdk:"patched_enforcement_trace_id"`
	PatchedDecisionEvidence   types.Int64  `tfsdk:"patched_decision_evidence"`
	PatchedDeepLLMEnrichment  types.Int64  `tfsdk:"patched_deepllm_enrichment"`
	RowIDsJSON                types.String `tfsdk:"row_ids_json"`
	ExecutedAt                types.String `tfsdk:"executed_at"`
}

func NewDecisionFieldBackfillResource() resource.Resource {
	return &decisionFieldBackfillResource{}
}

func (r *decisionFieldBackfillResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_decision_field_backfill"
}

func (r *decisionFieldBackfillResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Backfills normalized decision evidence fields for behavioral events.",
		Attributes: map[string]schema.Attribute{
			"id":        schema.StringAttribute{Computed: true, Description: "Synthetic execution ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id": schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"trigger":   schema.StringAttribute{Optional: true, Description: "Change this value to force a re-run.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of candidate rows to evaluate (1-5000).",
				Validators: []validator.Int64{
					int64validator.Between(1, 5000),
				},
			},
			"window_hours": schema.Int64Attribute{
				Optional:    true,
				Description: "Trailing lookback window in hours (1-2880).",
				Validators: []validator.Int64{
					int64validator.Between(1, 24*120),
				},
			},
			"include_blocked_events": schema.BoolAttribute{Optional: true, Description: "Include blocked events in candidate selection."},
			"dry_run":                schema.BoolAttribute{Optional: true, Description: "Preview candidate patches without persisting updates."},
			"examined":               schema.Int64Attribute{Computed: true, Description: "Rows scanned by the backfill operation."},
			"candidates":             schema.Int64Attribute{Computed: true, Description: "Rows eligible for decision-field patching."},
			"updated":                schema.Int64Attribute{Computed: true, Description: "Rows updated when dry_run=false."},
			"would_update":           schema.Int64Attribute{Computed: true, Description: "Rows that would be updated when dry_run=true."},
			"skipped_no_change":      schema.Int64Attribute{Computed: true, Description: "Eligible rows skipped because no field changes were required."},
			"patched_violation_id":   schema.Int64Attribute{Computed: true, Description: "Rows where violation_id was patched."},
			"patched_decision_reason_code": schema.Int64Attribute{
				Computed:    true,
				Description: "Rows where decision_reason_code was patched.",
			},
			"patched_authorization_decision": schema.Int64Attribute{
				Computed:    true,
				Description: "Rows where authorization_decision was patched.",
			},
			"patched_enforcement_trace_id": schema.Int64Attribute{
				Computed:    true,
				Description: "Rows where enforcement_trace_id was patched.",
			},
			"patched_decision_evidence": schema.Int64Attribute{
				Computed:    true,
				Description: "Rows where decision_evidence was patched.",
			},
			"patched_deepllm_enrichment": schema.Int64Attribute{
				Computed:    true,
				Description: "Rows where deepllm_enrichment was patched.",
			},
			"row_ids_json": schema.StringAttribute{
				Computed:    true,
				Description: "Candidate row IDs as a JSON array.",
			},
			"executed_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when backfill execution completed.",
			},
		},
	}
}

func (r *decisionFieldBackfillResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *decisionFieldBackfillResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan decisionFieldBackfillModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, err := r.runBackfill(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Decision field backfill failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *decisionFieldBackfillResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state decisionFieldBackfillModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *decisionFieldBackfillResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan decisionFieldBackfillModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, err := r.runBackfill(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Decision field backfill failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *decisionFieldBackfillResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No remote delete operation.
}

func (r *decisionFieldBackfillResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importID := strings.TrimSpace(req.ID)
	if importID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use any non-empty ID, for example a prior executed_at timestamp.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), importID)...)
}

func (r *decisionFieldBackfillResource) runBackfill(ctx context.Context, plan decisionFieldBackfillModel) (decisionFieldBackfillModel, error) {
	limit := int64(500)
	if !plan.Limit.IsNull() && !plan.Limit.IsUnknown() && plan.Limit.ValueInt64() > 0 {
		limit = plan.Limit.ValueInt64()
	}
	windowHours := int64(24 * 30)
	if !plan.WindowHours.IsNull() && !plan.WindowHours.IsUnknown() && plan.WindowHours.ValueInt64() > 0 {
		windowHours = plan.WindowHours.ValueInt64()
	}
	includeBlockedEvents := true
	if !plan.IncludeBlockedEvents.IsNull() && !plan.IncludeBlockedEvents.IsUnknown() {
		includeBlockedEvents = plan.IncludeBlockedEvents.ValueBool()
	}
	dryRun := false
	if !plan.DryRun.IsNull() && !plan.DryRun.IsUnknown() {
		dryRun = plan.DryRun.ValueBool()
	}

	query := map[string]string{
		"limit":                  fmt.Sprintf("%d", limit),
		"window_hours":           fmt.Sprintf("%d", windowHours),
		"include_blocked_events": fmt.Sprintf("%t", includeBlockedEvents),
		"dry_run":                fmt.Sprintf("%t", dryRun),
	}
	row, err := r.client.BackfillGovernanceDecisionFields(ctx, query, nil)
	if err != nil {
		return decisionFieldBackfillModel{}, err
	}

	executedAt := time.Now().UTC().Format(time.RFC3339)
	id := fmt.Sprintf("%s/%s", r.tenantID, executedAt)
	next := plan
	next.ID = types.StringValue(id)
	next.TenantID = types.StringValue(r.tenantID)
	next.Limit = types.Int64Value(limit)
	next.WindowHours = types.Int64Value(windowHours)
	next.IncludeBlockedEvents = types.BoolValue(includeBlockedEvents)
	next.DryRun = types.BoolValue(dryRun)
	next.Examined = types.Int64Value(tfhelpers.GetInt64(row, "examined"))
	next.Candidates = types.Int64Value(tfhelpers.GetInt64(row, "candidates"))
	next.Updated = types.Int64Value(tfhelpers.GetInt64(row, "updated"))
	next.WouldUpdate = types.Int64Value(tfhelpers.GetInt64(row, "would_update"))
	next.SkippedNoChange = types.Int64Value(tfhelpers.GetInt64(row, "skipped_no_change"))
	next.PatchedViolationID = types.Int64Value(tfhelpers.GetInt64(row, "patched_violation_id"))
	next.PatchedDecisionReasonCode = types.Int64Value(tfhelpers.GetInt64(row, "patched_decision_reason_code"))
	next.PatchedAuthorization = types.Int64Value(tfhelpers.GetInt64(row, "patched_authorization_decision"))
	next.PatchedTraceID = types.Int64Value(tfhelpers.GetInt64(row, "patched_enforcement_trace_id"))
	next.PatchedDecisionEvidence = types.Int64Value(tfhelpers.GetInt64(row, "patched_decision_evidence"))
	next.PatchedDeepLLMEnrichment = types.Int64Value(tfhelpers.GetInt64(row, "patched_deepllm_enrichment"))
	next.RowIDsJSON = types.StringValue(tfhelpers.ToJSONArrayString(row["row_ids"]))
	next.ExecutedAt = types.StringValue(executedAt)
	return next, nil
}
