package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &mcpVendorsDataSource{}

type mcpVendorsDataSource struct {
	client *client.Client
}

type mcpVendorsDataSourceModel struct {
	Approved     types.Bool   `tfsdk:"approved"`
	Total        types.Int64  `tfsdk:"total"`
	DataJSON     types.String `tfsdk:"data_json"`
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewMCPVendorsDataSource() datasource.DataSource {
	return &mcpVendorsDataSource{}
}

func (d *mcpVendorsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mcp_vendors"
}

func (d *mcpVendorsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists MCP vendor registry entries for the tenant.",
		Attributes: map[string]schema.Attribute{
			"approved": schema.BoolAttribute{
				Optional:    true,
				Description: "Optional filter for approved vendors only.",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total rows returned.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Vendor rows as JSON array.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Response envelope as JSON.",
			},
		},
	}
}

func (d *mcpVendorsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *mcpVendorsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state mcpVendorsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var approved *bool
	if !state.Approved.IsNull() && !state.Approved.IsUnknown() {
		value := state.Approved.ValueBool()
		approved = &value
	}

	rows, err := d.client.ListMCPVendors(ctx, approved)
	if err != nil {
		resp.Diagnostics.AddError("Error listing MCP vendors", err.Error())
		return
	}

	envelope := map[string]any{
		"data":  rows,
		"total": len(rows),
	}
	state.Total = types.Int64Value(int64(len(rows)))
	state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(rows))
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(envelope))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
