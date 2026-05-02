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

var _ datasource.DataSource = &governanceToolsDataSource{}

type governanceToolsDataSource struct {
	client *client.Client
}

type governanceToolsModel struct {
	WindowHours types.Int64  `tfsdk:"window_hours"`
	Limit       types.Int64  `tfsdk:"limit"`
	Total       types.Int64  `tfsdk:"total"`
	DataJSON    types.String `tfsdk:"data_json"`
}

func NewGovernanceToolsDataSource() datasource.DataSource {
	return &governanceToolsDataSource{}
}

func (d *governanceToolsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_tools"
}

func (d *governanceToolsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads aggregated governance telemetry grouped by tool.",
		Attributes: map[string]schema.Attribute{
			"window_hours": schema.Int64Attribute{Optional: true, Description: "Trailing window in hours."},
			"limit":        schema.Int64Attribute{Optional: true, Description: "Maximum tools to return."},
			"total":        schema.Int64Attribute{Computed: true, Description: "Total matching tools."},
			"data_json":    schema.StringAttribute{Computed: true, Description: "Tool telemetry rows as JSON array."},
		},
	}
}

func (d *governanceToolsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governanceToolsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state governanceToolsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	if !state.WindowHours.IsNull() && !state.WindowHours.IsUnknown() {
		query["window_hours"] = strconv.FormatInt(state.WindowHours.ValueInt64(), 10)
	}
	if !state.Limit.IsNull() && !state.Limit.IsUnknown() {
		query["limit"] = strconv.FormatInt(state.Limit.ValueInt64(), 10)
	}

	result, err := d.client.ListGovernanceTools(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance tools", err.Error())
		return
	}

	state.Total = types.Int64Value(tfhelpers.GetInt64(result, "total"))
	if raw, ok := result["data"]; ok {
		state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(raw))
	} else {
		state.DataJSON = types.StringValue("[]")
	}
	if v := tfhelpers.GetInt64(result, "window_hours"); v > 0 {
		state.WindowHours = types.Int64Value(v)
	}
	if v := tfhelpers.GetInt64(result, "limit"); v > 0 {
		state.Limit = types.Int64Value(v)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
