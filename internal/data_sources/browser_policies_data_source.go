package data_sources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &browserPoliciesDataSource{}

type browserPoliciesDataSource struct {
	client *client.Client
}

type browserPoliciesModel struct {
	Provider types.String `tfsdk:"provider"`
	Total    types.Int64  `tfsdk:"total"`
	DataJSON types.String `tfsdk:"data_json"`
}

func NewBrowserPoliciesDataSource() datasource.DataSource {
	return &browserPoliciesDataSource{}
}

func (d *browserPoliciesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_browser_policies"
}

func (d *browserPoliciesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads browser policies with optional provider filter.",
		Attributes: map[string]schema.Attribute{
			"provider": schema.StringAttribute{
				Optional:    true,
				Description: "Optional browser provider filter.",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total policies returned.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Browser policy rows as JSON array.",
			},
		},
	}
}

func (d *browserPoliciesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *browserPoliciesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state browserPoliciesModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	provider := strings.TrimSpace(state.Provider.ValueString())
	rows, err := d.client.ListBrowserPolicies(ctx, provider)
	if err != nil {
		resp.Diagnostics.AddError("Error reading browser policies", err.Error())
		return
	}

	if provider == "" {
		state.Provider = types.StringNull()
	} else {
		state.Provider = types.StringValue(provider)
	}
	state.Total = types.Int64Value(int64(len(rows)))
	state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(rows))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
