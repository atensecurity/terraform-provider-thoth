package data_sources

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &governanceEvidenceSLOsDataSource{}

type governanceEvidenceSLOsDataSource struct {
	client *client.Client
}

type governanceEvidenceSLOsModel struct {
	WindowHours    types.Int64  `tfsdk:"window_hours"`
	ScanLimit      types.Int64  `tfsdk:"scan_limit"`
	TenantID       types.String `tfsdk:"tenant_id"`
	GeneratedAt    types.String `tfsdk:"generated_at"`
	Passed         types.Bool   `tfsdk:"passed"`
	FailuresJSON   types.String `tfsdk:"failures_json"`
	ThresholdsJSON types.String `tfsdk:"thresholds_json"`
	MetricsJSON    types.String `tfsdk:"metrics_json"`

	RowsScanned                        types.Int64   `tfsdk:"rows_scanned"`
	ViolationRelevantRows              types.Int64   `tfsdk:"violation_relevant_rows"`
	ViolationIDPresenceRate            types.Float64 `tfsdk:"violation_id_presence_rate"`
	DecisionReasonCodeCoverage         types.Float64 `tfsdk:"decision_reason_code_coverage"`
	PolicyReferenceCoverageNonAllow    types.Float64 `tfsdk:"policy_reference_coverage_non_allow"`
	EvidenceChainVerificationSuccess   types.Float64 `tfsdk:"evidence_chain_verification_success"`
	DeepLLMEnrichmentJoinRate          types.Float64 `tfsdk:"deepllm_enrichment_join_rate"`
	DecisionToAPIVisibilityLatencyP95S types.Float64 `tfsdk:"decision_to_api_visibility_latency_p95_seconds"`
}

func NewGovernanceEvidenceSLOsDataSource() datasource.DataSource {
	return &governanceEvidenceSLOsDataSource{}
}

func (d *governanceEvidenceSLOsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_evidence_slos"
}

func (d *governanceEvidenceSLOsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads decision-evidence quality SLO metrics for Thoth governance telemetry.",
		Attributes: map[string]schema.Attribute{
			"window_hours": schema.Int64Attribute{Optional: true, Description: "Trailing window in hours."},
			"scan_limit":   schema.Int64Attribute{Optional: true, Description: "Maximum behavioral event rows to scan."},
			"tenant_id":    schema.StringAttribute{Computed: true, Description: "Tenant ID in the computed SLO report."},
			"generated_at": schema.StringAttribute{Computed: true, Description: "RFC3339 timestamp for report generation."},
			"passed":       schema.BoolAttribute{Computed: true, Description: "True when all evidence SLO thresholds pass."},
			"failures_json": schema.StringAttribute{
				Computed:    true,
				Description: "Failure identifiers as a JSON array when thresholds do not pass.",
			},
			"thresholds_json": schema.StringAttribute{
				Computed:    true,
				Description: "SLO thresholds as a JSON object.",
			},
			"metrics_json": schema.StringAttribute{
				Computed:    true,
				Description: "Raw SLO metrics object as JSON.",
			},
			"rows_scanned":                        schema.Int64Attribute{Computed: true, Description: "Behavioral event rows scanned."},
			"violation_relevant_rows":             schema.Int64Attribute{Computed: true, Description: "Rows considered relevant for violation-id presence coverage."},
			"violation_id_presence_rate":          schema.Float64Attribute{Computed: true, Description: "Coverage ratio for violation ID presence on relevant rows."},
			"decision_reason_code_coverage":       schema.Float64Attribute{Computed: true, Description: "Coverage ratio for decision_reason_code population."},
			"policy_reference_coverage_non_allow": schema.Float64Attribute{Computed: true, Description: "Coverage ratio for policy references on non-ALLOW decisions."},
			"evidence_chain_verification_success": schema.Float64Attribute{Computed: true, Description: "Coverage ratio for chain verification fields on candidate rows."},
			"deepllm_enrichment_join_rate":        schema.Float64Attribute{Computed: true, Description: "Coverage ratio for DeepLLM enrichment joins by enforcement trace ID."},
			"decision_to_api_visibility_latency_p95_seconds": schema.Float64Attribute{
				Computed:    true,
				Description: "P95 decision-to-API visibility latency in seconds.",
			},
		},
	}
}

func (d *governanceEvidenceSLOsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governanceEvidenceSLOsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state governanceEvidenceSLOsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	if !state.WindowHours.IsNull() && !state.WindowHours.IsUnknown() {
		query["window_hours"] = strconv.FormatInt(state.WindowHours.ValueInt64(), 10)
	}
	if !state.ScanLimit.IsNull() && !state.ScanLimit.IsUnknown() {
		query["scan_limit"] = strconv.FormatInt(state.ScanLimit.ValueInt64(), 10)
	}

	result, err := d.client.GetGovernanceEvidenceSLOs(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance evidence SLOs", err.Error())
		return
	}

	metrics := tfhelpers.GetMap(result, "metrics")
	thresholds := tfhelpers.GetMap(result, "thresholds")
	state.TenantID = nullableString(result, "tenant_id")
	state.GeneratedAt = nullableString(result, "generated_at")
	state.Passed = types.BoolValue(tfhelpers.GetBool(result, "passed"))
	state.FailuresJSON = types.StringValue(tfhelpers.ToJSONArrayString(result["failures"]))
	state.ThresholdsJSON = types.StringValue(tfhelpers.ToJSONString(thresholds))
	state.MetricsJSON = types.StringValue(tfhelpers.ToJSONString(metrics))

	if v := tfhelpers.GetInt64(result, "window_hours"); v > 0 {
		state.WindowHours = types.Int64Value(v)
	}
	if v := tfhelpers.GetInt64(result, "scan_limit"); v > 0 {
		state.ScanLimit = types.Int64Value(v)
	}

	state.RowsScanned = types.Int64Value(tfhelpers.GetInt64(metrics, "rows_scanned"))
	state.ViolationRelevantRows = types.Int64Value(tfhelpers.GetInt64(metrics, "violation_relevant_rows"))
	state.ViolationIDPresenceRate = types.Float64Value(tfhelpers.GetFloat64(metrics, "violation_id_presence_rate"))
	state.DecisionReasonCodeCoverage = types.Float64Value(tfhelpers.GetFloat64(metrics, "decision_reason_code_coverage"))
	state.PolicyReferenceCoverageNonAllow = types.Float64Value(tfhelpers.GetFloat64(metrics, "policy_reference_coverage_non_allow"))
	state.EvidenceChainVerificationSuccess = types.Float64Value(tfhelpers.GetFloat64(metrics, "evidence_chain_verification_success"))
	state.DeepLLMEnrichmentJoinRate = types.Float64Value(tfhelpers.GetFloat64(metrics, "deepllm_enrichment_join_rate"))
	state.DecisionToAPIVisibilityLatencyP95S = types.Float64Value(tfhelpers.GetFloat64(metrics, "decision_to_api_visibility_latency_p95_seconds"))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
