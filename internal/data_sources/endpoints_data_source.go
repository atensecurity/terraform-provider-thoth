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

var _ datasource.DataSource = &endpointsDataSource{}

type endpointsDataSource struct {
	client *client.Client
}

type endpointsModel struct {
	Environment types.String `tfsdk:"environment"`
	FleetID     types.String `tfsdk:"fleet_id"`
	Total       types.Int64  `tfsdk:"total"`
	DataJSON    types.String `tfsdk:"data_json"`
}

func NewEndpointsDataSource() datasource.DataSource {
	return &endpointsDataSource{}
}

func (d *endpointsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_endpoints"
}

func (d *endpointsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads endpoint inventory with optional environment and fleet filters.",
		Attributes: map[string]schema.Attribute{
			"environment": schema.StringAttribute{
				Optional:    true,
				Description: "Optional environment filter (for example: dev, staging, prod).",
			},
			"fleet_id": schema.StringAttribute{
				Optional:    true,
				Description: "Optional fleet ID filter.",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total endpoints returned after filters.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Endpoint rows as JSON array.",
			},
		},
	}
}

func (d *endpointsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *endpointsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state endpointsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	environment := strings.TrimSpace(state.Environment.ValueString())
	fleetID := strings.TrimSpace(state.FleetID.ValueString())
	rows, err := d.client.ListEndpoints(ctx, environment, fleetID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading endpoints", err.Error())
		return
	}

	state.Total = types.Int64Value(int64(len(rows)))
	state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(rows))
	if environment == "" {
		state.Environment = types.StringNull()
	} else {
		state.Environment = types.StringValue(environment)
	}
	if fleetID == "" {
		state.FleetID = types.StringNull()
	} else {
		state.FleetID = types.StringValue(fleetID)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
