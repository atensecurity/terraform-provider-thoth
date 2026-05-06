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

var _ datasource.DataSource = &governanceDay7ReportDataSource{}

type governanceDay7ReportDataSource struct {
	client *client.Client
}

type governanceDay7ReportModel struct {
	Days         types.Int64  `tfsdk:"days"`
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewGovernanceDay7ReportDataSource() datasource.DataSource {
	return &governanceDay7ReportDataSource{}
}

func (d *governanceDay7ReportDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_day7_report"
}

func (d *governanceDay7ReportDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads the governance day-7 report payload for the tenant.",
		Attributes: map[string]schema.Attribute{
			"days": schema.Int64Attribute{
				Optional:    true,
				Description: "Optional report window in days.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Day-7 report payload as JSON.",
			},
		},
	}
}

func (d *governanceDay7ReportDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governanceDay7ReportDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state governanceDay7ReportModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	if !state.Days.IsNull() && !state.Days.IsUnknown() && state.Days.ValueInt64() > 0 {
		query["days"] = strconv.FormatInt(state.Days.ValueInt64(), 10)
	}

	result, err := d.client.GetDay7Report(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance day-7 report", err.Error())
		return
	}

	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
