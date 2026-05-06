package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &browserProvidersDataSource{}

type browserProvidersDataSource struct {
	client *client.Client
}

type browserProvidersModel struct {
	Total    types.Int64  `tfsdk:"total"`
	DataJSON types.String `tfsdk:"data_json"`
}

func NewBrowserProvidersDataSource() datasource.DataSource {
	return &browserProvidersDataSource{}
}

func (d *browserProvidersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_browser_providers"
}

func (d *browserProvidersDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads configured browser providers for the tenant.",
		Attributes: map[string]schema.Attribute{
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total providers returned.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Browser provider rows as JSON array.",
			},
		},
	}
}

func (d *browserProvidersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *browserProvidersDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state browserProvidersModel

	rows, err := d.client.ListBrowserProviders(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading browser providers", err.Error())
		return
	}

	state.Total = types.Int64Value(int64(len(rows)))
	state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(rows))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
