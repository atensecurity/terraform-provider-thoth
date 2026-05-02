package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &apiKeyMetricsDataSource{}

type apiKeyMetricsDataSource struct {
	client *client.Client
}

type apiKeyMetricsModel struct {
	KeyUsage24h   types.Int64   `tfsdk:"key_usage_24h"`
	RedTeamTests  types.Int64   `tfsdk:"red_team_tests"`
	AvgLatencyMs  types.Float64 `tfsdk:"avg_latency_ms"`
	ActiveSDKKeys types.Int64   `tfsdk:"active_sdk_keys"`
	MetricsJSON   types.String  `tfsdk:"metrics_json"`
}

func NewAPIKeyMetricsDataSource() datasource.DataSource {
	return &apiKeyMetricsDataSource{}
}

func (d *apiKeyMetricsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_key_metrics"
}

func (d *apiKeyMetricsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads live API key/runtime usage metrics for the current tenant.",
		Attributes: map[string]schema.Attribute{
			"key_usage_24h":   schema.Int64Attribute{Computed: true, Description: "Count of API key authorizations over trailing 24h."},
			"red_team_tests":  schema.Int64Attribute{Computed: true, Description: "Count of red-team tests over trailing 24h."},
			"avg_latency_ms":  schema.Float64Attribute{Computed: true, Description: "Average authorization latency in milliseconds."},
			"active_sdk_keys": schema.Int64Attribute{Computed: true, Description: "Active SDK keys count."},
			"metrics_json":    schema.StringAttribute{Computed: true, Description: "Raw metrics payload as JSON."},
		},
	}
}

func (d *apiKeyMetricsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *apiKeyMetricsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	metrics, err := d.client.GetAPIKeyMetrics(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading API key metrics", err.Error())
		return
	}

	state := apiKeyMetricsModel{
		KeyUsage24h:   types.Int64Value(tfhelpers.GetInt64(metrics, "key_usage_24h")),
		RedTeamTests:  types.Int64Value(tfhelpers.GetInt64(metrics, "red_team_tests")),
		AvgLatencyMs:  types.Float64Value(tfhelpers.GetFloat64(metrics, "avg_latency_ms")),
		ActiveSDKKeys: types.Int64Value(tfhelpers.GetInt64(metrics, "active_sdk_keys")),
		MetricsJSON:   types.StringValue(tfhelpers.ToJSONString(metrics)),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
