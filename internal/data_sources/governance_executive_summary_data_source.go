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

var _ datasource.DataSource = &governanceExecutiveSummaryDataSource{}

type governanceExecutiveSummaryDataSource struct {
	client *client.Client
}

type governanceExecutiveSummaryModel struct {
	Days         types.Int64   `tfsdk:"days"`
	Rate         types.Float64 `tfsdk:"rate"`
	ResponseJSON types.String  `tfsdk:"response_json"`
}

func NewGovernanceExecutiveSummaryDataSource() datasource.DataSource {
	return &governanceExecutiveSummaryDataSource{}
}

func (d *governanceExecutiveSummaryDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_governance_executive_summary"
}

func (d *governanceExecutiveSummaryDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Description: "Reads board-ready executive summary metrics for governance posture and cost signals.",
		Attributes: map[string]schema.Attribute{
			"days": schema.Int64Attribute{
				Optional:    true,
				Description: "Optional lookback window in days.",
			},
			"rate": schema.Float64Attribute{
				Optional:    true,
				Description: "Optional custom pricing rate in USD per 1K tokens.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Executive summary payload as JSON.",
			},
		},
	}
}

func (d *governanceExecutiveSummaryDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governanceExecutiveSummaryDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var state governanceExecutiveSummaryModel
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

	result, err := d.client.GetExecutiveSummary(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance executive summary", err.Error())
		return
	}

	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
