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

var _ datasource.DataSource = &governanceCostReportDataSource{}

type governanceCostReportDataSource struct {
	client *client.Client
}

type governanceCostReportModel struct {
	Days         types.Int64   `tfsdk:"days"`
	Rate         types.Float64 `tfsdk:"rate"`
	ResponseJSON types.String  `tfsdk:"response_json"`
}

func NewGovernanceCostReportDataSource() datasource.DataSource {
	return &governanceCostReportDataSource{}
}

func (d *governanceCostReportDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_cost_report"
}

func (d *governanceCostReportDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads governance cost report payload for token usage and spend.",
		Attributes: map[string]schema.Attribute{
			"days": schema.Int64Attribute{
				Optional:    true,
				Description: "Optional reporting window in days.",
			},
			"rate": schema.Float64Attribute{
				Optional:    true,
				Description: "Optional model cost rate per 1K tokens.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Cost report payload as JSON.",
			},
		},
	}
}

func (d *governanceCostReportDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governanceCostReportDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state governanceCostReportModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	if !state.Days.IsNull() && !state.Days.IsUnknown() && state.Days.ValueInt64() > 0 {
		query["days"] = strconv.FormatInt(state.Days.ValueInt64(), 10)
	}
	if !state.Rate.IsNull() && !state.Rate.IsUnknown() && state.Rate.ValueFloat64() > 0 {
		query["rate"] = strconv.FormatFloat(state.Rate.ValueFloat64(), 'f', -1, 64)
	}

	result, err := d.client.GetCostReport(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance cost report", err.Error())
		return
	}

	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
