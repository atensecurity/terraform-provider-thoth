package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &billingMonthlyCostDataSource{}

type billingMonthlyCostDataSource struct {
	client *client.Client
}

type billingMonthlyCostModel struct {
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewBillingMonthlyCostDataSource() datasource.DataSource {
	return &billingMonthlyCostDataSource{}
}

func (d *billingMonthlyCostDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_billing_monthly_cost"
}

func (d *billingMonthlyCostDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads the tenant monthly billing cost summary.",
		Attributes: map[string]schema.Attribute{
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Monthly billing cost payload as JSON.",
			},
		},
	}
}

func (d *billingMonthlyCostDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *billingMonthlyCostDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state billingMonthlyCostModel
	out, err := d.client.GetBillingMonthlyCost(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading billing monthly cost", err.Error())
		return
	}
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(out))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
