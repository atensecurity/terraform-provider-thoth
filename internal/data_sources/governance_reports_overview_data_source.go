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

var _ datasource.DataSource = &governanceReportsOverviewDataSource{}

type governanceReportsOverviewDataSource struct {
	client *client.Client
}

type governanceReportsOverviewModel struct {
	Days                       types.Int64  `tfsdk:"days"`
	MCPDeviationAlerts         types.Int64  `tfsdk:"mcp_deviation_alerts"`
	MCPCriticalDeviationAlerts types.Int64  `tfsdk:"mcp_critical_deviation_alerts"`
	MCPDeviationByTypeJSON     types.String `tfsdk:"mcp_deviation_by_type_json"`
	ResponseJSON               types.String `tfsdk:"response_json"`
}

func NewGovernanceReportsOverviewDataSource() datasource.DataSource {
	return &governanceReportsOverviewDataSource{}
}

func (d *governanceReportsOverviewDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_reports_overview"
}

func (d *governanceReportsOverviewDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads governance reports overview dashboard data for the tenant.",
		Attributes: map[string]schema.Attribute{
			"days": schema.Int64Attribute{
				Optional:    true,
				Description: "Optional overview window in days.",
			},
			"mcp_deviation_alerts": schema.Int64Attribute{
				Computed:    true,
				Description: "Total MCP deviation alerts in the reporting window.",
			},
			"mcp_critical_deviation_alerts": schema.Int64Attribute{
				Computed:    true,
				Description: "Critical MCP deviation alerts in the reporting window.",
			},
			"mcp_deviation_by_type_json": schema.StringAttribute{
				Computed:    true,
				Description: "MCP deviation counts grouped by type as JSON array.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Reports overview payload as JSON.",
			},
		},
	}
}

func (d *governanceReportsOverviewDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governanceReportsOverviewDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state governanceReportsOverviewModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	if !state.Days.IsNull() && !state.Days.IsUnknown() && state.Days.ValueInt64() > 0 {
		query["days"] = strconv.FormatInt(state.Days.ValueInt64(), 10)
	}

	result, err := d.client.GetReportsOverview(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance reports overview", err.Error())
		return
	}

	alerts, critical := extractOverviewMCPDeviationCounts(result)
	state.MCPDeviationAlerts = types.Int64Value(alerts)
	state.MCPCriticalDeviationAlerts = types.Int64Value(critical)
	state.MCPDeviationByTypeJSON = types.StringValue(extractOverviewMCPDeviationByTypeJSON(result))
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func extractOverviewMCPDeviationCounts(result map[string]any) (int64, int64) {
	kpi := tfhelpers.GetMap(result, "kpi")
	return tfhelpers.GetInt64(kpi, "mcp_deviation_alerts"), tfhelpers.GetInt64(kpi, "mcp_critical_deviation_alerts")
}

func extractOverviewMCPDeviationByTypeJSON(result map[string]any) string {
	return tfhelpers.ToJSONArrayString(result["mcp_deviation_by_type"])
}
