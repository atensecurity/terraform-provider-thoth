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

var _ datasource.DataSource = &fleetsDataSource{}

type fleetsDataSource struct {
	client *client.Client
}

type fleetsModel struct {
	Status   types.String `tfsdk:"status"`
	Region   types.String `tfsdk:"region"`
	Provider types.String `tfsdk:"provider"`
	Total    types.Int64  `tfsdk:"total"`
	DataJSON types.String `tfsdk:"data_json"`
}

func NewFleetsDataSource() datasource.DataSource {
	return &fleetsDataSource{}
}

func (d *fleetsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fleets"
}

func (d *fleetsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads fleets with optional status, region, and provider filters.",
		Attributes: map[string]schema.Attribute{
			"status": schema.StringAttribute{
				Optional:    true,
				Description: "Optional fleet status filter.",
			},
			"region": schema.StringAttribute{
				Optional:    true,
				Description: "Optional region filter.",
			},
			"provider": schema.StringAttribute{
				Optional:    true,
				Description: "Optional provider filter.",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total fleets returned after filtering.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Fleet rows as JSON array.",
			},
		},
	}
}

func (d *fleetsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *fleetsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state fleetsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rows, err := d.client.ListFleets(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading fleets", err.Error())
		return
	}

	status := strings.TrimSpace(state.Status.ValueString())
	region := strings.TrimSpace(state.Region.ValueString())
	provider := strings.TrimSpace(state.Provider.ValueString())

	filtered := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if status != "" && !strings.EqualFold(strings.TrimSpace(tfhelpers.GetString(row, "status")), status) {
			continue
		}
		if region != "" && !strings.EqualFold(strings.TrimSpace(tfhelpers.GetString(row, "region")), region) {
			continue
		}
		if provider != "" && !strings.EqualFold(strings.TrimSpace(tfhelpers.GetString(row, "provider")), provider) {
			continue
		}
		filtered = append(filtered, row)
	}

	if status == "" {
		state.Status = types.StringNull()
	} else {
		state.Status = types.StringValue(status)
	}
	if region == "" {
		state.Region = types.StringNull()
	} else {
		state.Region = types.StringValue(region)
	}
	if provider == "" {
		state.Provider = types.StringNull()
	} else {
		state.Provider = types.StringValue(provider)
	}
	state.Total = types.Int64Value(int64(len(filtered)))
	state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(filtered))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
