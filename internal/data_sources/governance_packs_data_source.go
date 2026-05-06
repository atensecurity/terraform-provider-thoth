package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &governancePacksDataSource{}

type governancePacksDataSource struct {
	client *client.Client
}

type governancePacksModel struct {
	Total     types.Int64  `tfsdk:"total"`
	PacksJSON types.String `tfsdk:"packs_json"`
}

func NewGovernancePacksDataSource() datasource.DataSource {
	return &governancePacksDataSource{}
}

func (d *governancePacksDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_packs"
}

func (d *governancePacksDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads available compliance pack catalog entries.",
		Attributes: map[string]schema.Attribute{
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total number of packs returned.",
			},
			"packs_json": schema.StringAttribute{
				Computed:    true,
				Description: "Pack catalog rows as JSON array.",
			},
		},
	}
}

func (d *governancePacksDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governancePacksDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state governancePacksModel

	result, err := d.client.ListGovernancePacks(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance packs", err.Error())
		return
	}

	state.Total = types.Int64Value(tfhelpers.GetInt64(result, "total"))
	if raw, ok := result["packs"]; ok {
		state.PacksJSON = types.StringValue(tfhelpers.ToJSONArrayString(raw))
	} else {
		state.PacksJSON = types.StringValue("[]")
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
