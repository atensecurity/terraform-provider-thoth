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
	Days         types.Int64  `tfsdk:"days"`
	ResponseJSON types.String `tfsdk:"response_json"`
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

	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
