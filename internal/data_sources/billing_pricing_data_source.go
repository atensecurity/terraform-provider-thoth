package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &billingPricingDataSource{}

type billingPricingDataSource struct {
	client *client.Client
}

type billingPricingModel struct {
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewBillingPricingDataSource() datasource.DataSource {
	return &billingPricingDataSource{}
}

func (d *billingPricingDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_billing_pricing"
}

func (d *billingPricingDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads the effective tenant billing pricing profile.",
		Attributes: map[string]schema.Attribute{
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Billing pricing payload as JSON.",
			},
		},
	}
}

func (d *billingPricingDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *billingPricingDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state billingPricingModel
	out, err := d.client.GetBillingPricing(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading billing pricing", err.Error())
		return
	}
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(out))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
