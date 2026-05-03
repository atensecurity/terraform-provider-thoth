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

var _ resource.Resource = &evidenceBackfillResource{}
var _ resource.ResourceWithImportState = &evidenceBackfillResource{}

type evidenceBackfillResource struct {
	client   *client.Client
	tenantID string
}

type evidenceBackfillModel struct {
	ID                   types.String `tfsdk:"id"`
	TenantID             types.String `tfsdk:"tenant_id"`
	Trigger              types.String `tfsdk:"trigger"`
	Limit                types.Int64  `tfsdk:"limit"`
	IncludeBlockedEvents types.Bool   `tfsdk:"include_blocked_events"`
	IntegrationID        types.String `tfsdk:"integration_id"`
	DryRun               types.Bool   `tfsdk:"dry_run"`
	SourceCollection     types.String `tfsdk:"source_collection"`
	Examined             types.Int64  `tfsdk:"examined"`
	Candidates           types.Int64  `tfsdk:"candidates"`
	Created              types.Int64  `tfsdk:"created"`
	WouldCreate          types.Int64  `tfsdk:"would_create"`
	SkippedExisting      types.Int64  `tfsdk:"skipped_existing"`
	EvidenceIDsJSON      types.String `tfsdk:"evidence_ids_json"`
	ExecutedAt           types.String `tfsdk:"executed_at"`
}

func NewEvidenceBackfillResource() resource.Resource {
	return &evidenceBackfillResource{}
}

func (r *evidenceBackfillResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_evidence_backfill"
}

func (r *evidenceBackfillResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Backfills governance evidence records from Thoth behavioral events.",
		Attributes: map[string]schema.Attribute{
			"id":        schema.StringAttribute{Computed: true, Description: "Synthetic execution ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id": schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"trigger":   schema.StringAttribute{Optional: true, Description: "Change this value to force a re-run.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of candidate events to evaluate (1-1000).",
				Validators: []validator.Int64{
					int64validator.Between(1, 1000),
				},
			},
			"include_blocked_events": schema.BoolAttribute{Optional: true, Description: "Include blocked decisions in addition to explicit violations."},
			"integration_id":         schema.StringAttribute{Optional: true, Description: "Optional integration ID stamped on created evidence records."},
			"dry_run":                schema.BoolAttribute{Optional: true, Description: "When true, preview records without persisting evidence."},
			"source_collection":      schema.StringAttribute{Computed: true, Description: "Source collection used by the backfill endpoint."},
			"examined":               schema.Int64Attribute{Computed: true, Description: "Number of source events examined."},
			"candidates":             schema.Int64Attribute{Computed: true, Description: "Number of events that qualified for backfill."},
			"created":                schema.Int64Attribute{Computed: true, Description: "Number of new evidence records created."},
			"would_create":           schema.Int64Attribute{Computed: true, Description: "Number of records that would be created in dry-run mode."},
			"skipped_existing":       schema.Int64Attribute{Computed: true, Description: "Number of candidates skipped due to existing evidence."},
			"evidence_ids_json":      schema.StringAttribute{Computed: true, Description: "Created or candidate evidence IDs as JSON array."},
			"executed_at":            schema.StringAttribute{Computed: true, Description: "Timestamp when backfill was executed."},
		},
	}
}

func (r *evidenceBackfillResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *evidenceBackfillResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan evidenceBackfillModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, err := r.runBackfill(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Evidence backfill failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *evidenceBackfillResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state evidenceBackfillModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// No historical GET endpoint; keep last execution state.
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *evidenceBackfillResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan evidenceBackfillModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, err := r.runBackfill(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Evidence backfill failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *evidenceBackfillResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No remote delete operation.
}

func (r *evidenceBackfillResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importID := strings.TrimSpace(req.ID)
	if importID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use any non-empty ID, for example a prior executed_at timestamp.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), importID)...)
}

func (r *evidenceBackfillResource) runBackfill(ctx context.Context, plan evidenceBackfillModel) (evidenceBackfillModel, error) {
	limit := int64(200)
	if !plan.Limit.IsNull() && !plan.Limit.IsUnknown() && plan.Limit.ValueInt64() > 0 {
		limit = plan.Limit.ValueInt64()
	}
	includeBlockedEvents := true
	if !plan.IncludeBlockedEvents.IsNull() && !plan.IncludeBlockedEvents.IsUnknown() {
		includeBlockedEvents = plan.IncludeBlockedEvents.ValueBool()
	}
	dryRun := false
	if !plan.DryRun.IsNull() && !plan.DryRun.IsUnknown() {
		dryRun = plan.DryRun.ValueBool()
	}
	integrationID := strings.TrimSpace(plan.IntegrationID.ValueString())

	query := map[string]string{
		"limit":                  fmt.Sprintf("%d", limit),
		"include_blocked_events": fmt.Sprintf("%t", includeBlockedEvents),
		"dry_run":                fmt.Sprintf("%t", dryRun),
	}
	if integrationID != "" {
		query["integration_id"] = integrationID
	}

	row, err := r.client.BackfillGovernanceEvidence(ctx, query, nil)
	if err != nil {
		return evidenceBackfillModel{}, err
	}

	executedAt := time.Now().UTC().Format(time.RFC3339)
	id := fmt.Sprintf("%s/%s", r.tenantID, executedAt)

	next := plan
	next.ID = types.StringValue(id)
	next.TenantID = types.StringValue(r.tenantID)
	next.Limit = types.Int64Value(limit)
	next.IncludeBlockedEvents = types.BoolValue(includeBlockedEvents)
	next.DryRun = types.BoolValue(dryRun)
	if integrationID == "" {
		next.IntegrationID = types.StringNull()
	} else {
		next.IntegrationID = types.StringValue(integrationID)
	}
	next.SourceCollection = nullableString(row, "source_collection")
	next.Examined = types.Int64Value(tfhelpers.GetInt64(row, "examined"))
	next.Candidates = types.Int64Value(tfhelpers.GetInt64(row, "candidates"))
	next.Created = types.Int64Value(tfhelpers.GetInt64(row, "created"))
	next.WouldCreate = types.Int64Value(tfhelpers.GetInt64(row, "would_create"))
	next.SkippedExisting = types.Int64Value(tfhelpers.GetInt64(row, "skipped_existing"))
	next.EvidenceIDsJSON = types.StringValue(tfhelpers.ToJSONArrayString(row["evidence_ids"]))
	next.ExecutedAt = types.StringValue(executedAt)
	return next, nil
}
