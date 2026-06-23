package data_sources

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &governanceCostReportDataSource{}

type governanceCostReportDataSource struct {
	client *client.Client
}

type governanceCostReportModel struct {
	Days                    types.Int64   `tfsdk:"days"`
	Rate                    types.Float64 `tfsdk:"rate"`
	PricingSource           types.String  `tfsdk:"pricing_source"`
	PricingVersion          types.String  `tfsdk:"pricing_version"`
	PricingSHA256           types.String  `tfsdk:"pricing_sha256"`
	PricingUpdatedAt        types.String  `tfsdk:"pricing_updated_at"`
	PricedWithCatalogCount  types.Int64   `tfsdk:"priced_with_catalog_count"`
	EventEstimatedFallbacks types.Int64   `tfsdk:"event_estimated_fallbacks"`
	FlatRateFallbacks       types.Int64   `tfsdk:"flat_rate_fallbacks"`
	UnresolvedModels        types.List    `tfsdk:"unresolved_models"`
	ResponseJSON            types.String  `tfsdk:"response_json"`
}

func NewGovernanceCostReportDataSource() datasource.DataSource {
	return &governanceCostReportDataSource{}
}

func (d *governanceCostReportDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_cost_report"
}

func (d *governanceCostReportDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads governance cost report payload for token usage and spend.",
		Attributes: map[string]schema.Attribute{
			"days": schema.Int64Attribute{
				Optional:    true,
				Description: "Optional reporting window in days.",
			},
			"rate": schema.Float64Attribute{
				Optional:    true,
				Description: "Optional model cost rate per 1K tokens.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Cost report payload as JSON.",
			},
			"pricing_source": schema.StringAttribute{
				Computed:    true,
				Description: "Pricing source used to compute model costs (for example litellm_catalog:path, litellm_catalog:url, event_estimated_cost, flat_rate_default).",
			},
			"pricing_version": schema.StringAttribute{
				Computed:    true,
				Description: "Pricing catalog version identifier (sha256 prefix) when catalog-backed pricing is active.",
			},
			"pricing_sha256": schema.StringAttribute{
				Computed:    true,
				Description: "SHA256 digest for the pricing catalog payload used by GovAPI.",
			},
			"pricing_updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "RFC3339 timestamp when GovAPI last refreshed pricing catalog data.",
			},
			"priced_with_catalog_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of provider/model rows priced directly from the model pricing catalog.",
			},
			"event_estimated_fallbacks": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of rows that used event-provided estimated_cost_usd fallback.",
			},
			"flat_rate_fallbacks": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of rows that used flat-rate per-1k fallback pricing.",
			},
			"unresolved_models": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Provider/model keys that did not match the pricing catalog and therefore required fallback pricing.",
			},
		},
	}
}

func (d *governanceCostReportDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governanceCostReportDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state governanceCostReportModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	if !state.Days.IsNull() && !state.Days.IsUnknown() && state.Days.ValueInt64() > 0 {
		query["days"] = strconv.FormatInt(state.Days.ValueInt64(), 10)
	}
	if !state.Rate.IsNull() && !state.Rate.IsUnknown() && state.Rate.ValueFloat64() > 0 {
		query["rate"] = strconv.FormatFloat(state.Rate.ValueFloat64(), 'f', -1, 64)
	}

	result, err := d.client.GetCostReport(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance cost report", err.Error())
		return
	}

	pricingEvidence := tfhelpers.GetMap(result, "pricing_evidence")
	state.PricingSource = types.StringValue(tfhelpers.GetString(result, "pricing_source"))
	state.PricingVersion = types.StringValue(tfhelpers.GetString(result, "pricing_version"))
	state.PricingSHA256 = types.StringValue(tfhelpers.GetString(result, "pricing_sha256"))
	state.PricingUpdatedAt = types.StringValue(tfhelpers.GetString(result, "pricing_updated_at"))
	state.PricedWithCatalogCount = types.Int64Value(tfhelpers.GetInt64(pricingEvidence, "priced_with_catalog_count"))
	state.EventEstimatedFallbacks = types.Int64Value(tfhelpers.GetInt64(pricingEvidence, "event_estimated_fallbacks"))
	state.FlatRateFallbacks = types.Int64Value(tfhelpers.GetInt64(pricingEvidence, "flat_rate_fallbacks"))
	state.UnresolvedModels = tfhelpers.StringSliceValue(tfhelpers.GetStringSlice(pricingEvidence, "unresolved_models"))
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
