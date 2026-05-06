package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &endpointStatsDataSource{}

type endpointStatsDataSource struct {
	client *client.Client
}

type endpointStatsModel struct {
	Total         types.Int64  `tfsdk:"total"`
	Managed       types.Int64  `tfsdk:"managed"`
	Unmanaged     types.Int64  `tfsdk:"unmanaged"`
	Online        types.Int64  `tfsdk:"online"`
	Quarantined   types.Int64  `tfsdk:"quarantined"`
	Stale         types.Int64  `tfsdk:"stale"`
	AtRisk        types.Int64  `tfsdk:"at_risk"`
	ProxyOutdated types.Int64  `tfsdk:"proxy_outdated"`
	LatestVersion types.String `tfsdk:"latest_version"`
	StatsJSON     types.String `tfsdk:"stats_json"`
}

func NewEndpointStatsDataSource() datasource.DataSource {
	return &endpointStatsDataSource{}
}

func (d *endpointStatsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_endpoint_stats"
}

func (d *endpointStatsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads aggregated endpoint fleet statistics.",
		Attributes: map[string]schema.Attribute{
			"total":          schema.Int64Attribute{Computed: true, Description: "Total endpoint count."},
			"managed":        schema.Int64Attribute{Computed: true, Description: "Managed endpoint count."},
			"unmanaged":      schema.Int64Attribute{Computed: true, Description: "Unmanaged endpoint count."},
			"online":         schema.Int64Attribute{Computed: true, Description: "Online endpoint count."},
			"quarantined":    schema.Int64Attribute{Computed: true, Description: "Quarantined endpoint count."},
			"stale":          schema.Int64Attribute{Computed: true, Description: "Stale endpoint count."},
			"at_risk":        schema.Int64Attribute{Computed: true, Description: "At-risk endpoint count."},
			"proxy_outdated": schema.Int64Attribute{Computed: true, Description: "Endpoints with outdated proxy version."},
			"latest_version": schema.StringAttribute{Computed: true, Description: "Latest expected endpoint proxy version."},
			"stats_json":     schema.StringAttribute{Computed: true, Description: "Raw stats payload as JSON."},
		},
	}
}

func (d *endpointStatsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *endpointStatsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state endpointStatsModel

	stats, err := d.client.GetEndpointStats(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading endpoint stats", err.Error())
		return
	}

	state.Total = types.Int64Value(tfhelpers.GetInt64(stats, "total"))
	state.Managed = types.Int64Value(tfhelpers.GetInt64(stats, "managed"))
	state.Unmanaged = types.Int64Value(tfhelpers.GetInt64(stats, "unmanaged"))
	state.Online = types.Int64Value(tfhelpers.GetInt64(stats, "online"))
	state.Quarantined = types.Int64Value(tfhelpers.GetInt64(stats, "quarantined"))
	state.Stale = types.Int64Value(tfhelpers.GetInt64(stats, "stale"))
	state.AtRisk = types.Int64Value(tfhelpers.GetInt64(stats, "at_risk"))
	state.ProxyOutdated = types.Int64Value(tfhelpers.GetInt64(stats, "proxy_outdated"))
	state.LatestVersion = nullableString(stats, "latest_version")
	state.StatsJSON = types.StringValue(tfhelpers.ToJSONString(stats))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
