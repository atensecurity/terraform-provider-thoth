package data_sources

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &reportDataDataSource{}

type reportDataDataSource struct {
	client *client.Client
}

type reportDataModel struct {
	ReportID     types.String `tfsdk:"report_id"`
	Cadence      types.String `tfsdk:"cadence"`
	Status       types.String `tfsdk:"status"`
	ReportType   types.String `tfsdk:"report_type"`
	AgentID      types.String `tfsdk:"agent_id"`
	ResponseJSON types.String `tfsdk:"response_json"`
	MetadataJSON types.String `tfsdk:"metadata_json"`
}

func NewReportDataDataSource() datasource.DataSource {
	return &reportDataDataSource{}
}

func (d *reportDataDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_report_data"
}

func (d *reportDataDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads unified AIRS report snapshots (latest or by ID) and exposes canonical JSON plus metadata.",
		Attributes: map[string]schema.Attribute{
			"report_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Report ID to fetch. Defaults to latest COMPLETED report.",
			},
			"cadence": schema.StringAttribute{
				Optional:    true,
				Description: "Optional cadence filter (for example: 7d, 30d, custom).",
			},
			"status": schema.StringAttribute{
				Optional:    true,
				Description: "Optional status filter (PENDING, COMPLETED, FAILED) when resolving latest report.",
			},
			"report_type": schema.StringAttribute{
				Optional:    true,
				Description: "Optional projection: full, metadata, governance, economic, dlp, forensic, post_approval_gap.",
			},
			"agent_id": schema.StringAttribute{
				Optional:    true,
				Description: "Optional consumer-side selector for downstream tooling workflows.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Canonical report payload JSON.",
			},
			"metadata_json": schema.StringAttribute{
				Computed:    true,
				Description: "Report metadata-only JSON (id, cadence, hash, generated_at, status, post_approval_gap).",
			},
		},
	}
}

func (d *reportDataDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *reportDataDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state reportDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	reportID := strings.TrimSpace(state.ReportID.ValueString())
	if reportID == "" {
		reportID = "latest"
	}

	query := map[string]string{}
	if cadence := strings.TrimSpace(state.Cadence.ValueString()); cadence != "" {
		query["cadence"] = cadence
	}
	if status := strings.TrimSpace(state.Status.ValueString()); status != "" {
		query["status"] = strings.ToUpper(status)
	}

	result, err := d.client.GetAIRSReport(ctx, reportID, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading AIRS report snapshot", err.Error())
		return
	}

	projection := strings.ToLower(strings.TrimSpace(state.ReportType.ValueString()))
	projected := projectReportResult(result, projection)
	metadata := extractReportMetadata(result)

	resolvedID := strings.TrimSpace(stringFromMapAny(result, "report_id"))
	if resolvedID == "" {
		resolvedID = reportID
	}
	state.ReportID = types.StringValue(resolvedID)
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(projected))
	state.MetadataJSON = types.StringValue(tfhelpers.ToJSONString(metadata))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func projectReportResult(result map[string]any, projection string) map[string]any {
	switch projection {
	case "", "full":
		return result
	case "metadata":
		return extractReportMetadata(result)
	case "governance":
		return map[string]any{"governance_metrics": result["governance_metrics"]}
	case "economic":
		return map[string]any{"economic_metrics": result["economic_metrics"]}
	case "dlp":
		return map[string]any{"dlp_metrics": result["dlp_metrics"]}
	case "forensic":
		return map[string]any{"forensic_ledger": result["forensic_ledger"]}
	case "post_approval_gap":
		return map[string]any{"post_approval_gap": result["post_approval_gap"]}
	default:
		return result
	}
}

func extractReportMetadata(result map[string]any) map[string]any {
	return map[string]any{
		"report_id":         result["report_id"],
		"tenant_id":         result["tenant_id"],
		"cadence":           result["cadence"],
		"time_range":        result["time_range"],
		"generated_at":      result["generated_at"],
		"status":            result["status"],
		"report_hash":       result["report_hash"],
		"post_approval_gap": result["post_approval_gap"],
	}
}

func stringFromMapAny(input map[string]any, key string) string {
	if input == nil {
		return ""
	}
	value, ok := input[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(encoded)
	}
}
