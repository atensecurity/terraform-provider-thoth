package data_sources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &fleetDataSource{}

type fleetDataSource struct {
	client *client.Client
}

type fleetModel struct {
	FleetID       types.String `tfsdk:"fleet_id"`
	Name          types.String `tfsdk:"name"`
	Status        types.String `tfsdk:"status"`
	Region        types.String `tfsdk:"region"`
	EndpointCount types.Int64  `tfsdk:"endpoint_count"`
	ResponseJSON  types.String `tfsdk:"response_json"`
}

func NewFleetDataSource() datasource.DataSource {
	return &fleetDataSource{}
}

func (d *fleetDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fleet"
}

func (d *fleetDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads details for a single fleet by fleet_id.",
		Attributes: map[string]schema.Attribute{
			"fleet_id": schema.StringAttribute{
				Required:    true,
				Description: "Fleet identifier.",
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "Fleet display name.",
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Fleet status.",
			},
			"region": schema.StringAttribute{
				Computed:    true,
				Description: "Fleet region.",
			},
			"endpoint_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Endpoint count for this fleet.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full fleet response payload as JSON.",
			},
		},
	}
}

func (d *fleetDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *fleetDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state fleetModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	fleetID := strings.TrimSpace(state.FleetID.ValueString())
	if fleetID == "" {
		resp.Diagnostics.AddAttributeError(path.Root("fleet_id"), "Missing fleet_id", "fleet_id must be set.")
		return
	}
	state.FleetID = types.StringValue(fleetID)

	row, err := d.client.GetFleet(ctx, fleetID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading fleet", err.Error())
		return
	}

	state.Name = nullableString(row, "name")
	state.Status = nullableString(row, "status")
	state.Region = nullableString(row, "region")
	state.EndpointCount = types.Int64Value(tfhelpers.GetInt64(row, "endpoint_count"))
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(row))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
