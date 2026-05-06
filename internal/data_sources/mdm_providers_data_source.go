package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &mdmProvidersDataSource{}

type mdmProvidersDataSource struct {
	client *client.Client
}

type mdmProvidersModel struct {
	Total    types.Int64  `tfsdk:"total"`
	DataJSON types.String `tfsdk:"data_json"`
}

func NewMDMProvidersDataSource() datasource.DataSource {
	return &mdmProvidersDataSource{}
}

func (d *mdmProvidersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mdm_providers"
}

func (d *mdmProvidersDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads configured MDM providers for the tenant.",
		Attributes: map[string]schema.Attribute{
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total providers returned.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "MDM provider rows as JSON array.",
			},
		},
	}
}

func (d *mdmProvidersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *mdmProvidersDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state mdmProvidersModel

	rows, err := d.client.ListMDMProviders(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading MDM providers", err.Error())
		return
	}

	state.Total = types.Int64Value(int64(len(rows)))
	state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(rows))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
