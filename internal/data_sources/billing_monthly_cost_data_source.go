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
	Tier                       types.String  `tfsdk:"tier"`
	ActionCostUSD              types.Float64 `tfsdk:"action_cost_usd"`
	PolicyChecksTotal          types.Int64   `tfsdk:"policy_checks_total"`
	GovernedIdentitiesObserved types.Int64   `tfsdk:"governed_identities_observed"`
	PolicyChecksCostUSD        types.Float64 `tfsdk:"policy_checks_cost_usd"`
	GovernedIdentityCostUSD    types.Float64 `tfsdk:"governed_identity_cost_usd"`
	CreditDiscountUSD          types.Float64 `tfsdk:"credit_discount_usd"`
	NetCostUSD                 types.Float64 `tfsdk:"net_cost_usd"`
	TotalCostUSD               types.Float64 `tfsdk:"total_cost_usd"`
	StripeInvoiceTotalUSD      types.Float64 `tfsdk:"stripe_invoice_total_usd"`
	StripeReconciliationUSD    types.Float64 `tfsdk:"stripe_reconciliation_usd"`
	ResponseJSON               types.String  `tfsdk:"response_json"`
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
			"tier": schema.StringAttribute{
				Computed:    true,
				Description: "Effective billing tier for the current month.",
			},
			"action_cost_usd": schema.Float64Attribute{
				Computed:    true,
				Description: "Current month action cost estimate in USD.",
			},
			"policy_checks_total": schema.Int64Attribute{
				Computed:    true,
				Description: "Observed policy checks for the current month.",
			},
			"governed_identities_observed": schema.Int64Attribute{
				Computed:    true,
				Description: "Observed governed identities for the current month.",
			},
			"policy_checks_cost_usd": schema.Float64Attribute{
				Computed:    true,
				Description: "Estimated policy-check meter cost in USD.",
			},
			"governed_identity_cost_usd": schema.Float64Attribute{
				Computed:    true,
				Description: "Estimated governed-identity meter cost in USD.",
			},
			"credit_discount_usd": schema.Float64Attribute{
				Computed:    true,
				Description: "Estimated prepaid-credit discount in USD.",
			},
			"net_cost_usd": schema.Float64Attribute{
				Computed:    true,
				Description: "Net estimated monthly cost in USD after discount.",
			},
			"total_cost_usd": schema.Float64Attribute{
				Computed:    true,
				Description: "Estimated total monthly cost in USD before external reconciliation adjustments.",
			},
			"stripe_invoice_total_usd": schema.Float64Attribute{
				Computed:    true,
				Description: "Stripe invoice total for current period in USD.",
			},
			"stripe_reconciliation_usd": schema.Float64Attribute{
				Computed:    true,
				Description: "Difference between Stripe invoice totals and metered estimate.",
			},
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
	pilotEstimate := tfhelpers.GetMap(out, "pilot_meter_estimate")
	stripeRecon := tfhelpers.GetMap(out, "stripe_reconciliation")
	state.Tier = types.StringValue(tfhelpers.GetString(out, "tier"))
	state.ActionCostUSD = types.Float64Value(tfhelpers.GetFloat64(out, "action_cost_usd"))
	state.PolicyChecksTotal = types.Int64Value(tfhelpers.GetInt64(pilotEstimate, "policy_checks_total"))
	state.GovernedIdentitiesObserved = types.Int64Value(tfhelpers.GetInt64(pilotEstimate, "governed_identities_observed"))
	state.PolicyChecksCostUSD = types.Float64Value(tfhelpers.GetFloat64(pilotEstimate, "policy_checks_cost_usd"))
	state.GovernedIdentityCostUSD = types.Float64Value(tfhelpers.GetFloat64(pilotEstimate, "governed_identity_cost_usd"))
	state.CreditDiscountUSD = types.Float64Value(tfhelpers.GetFloat64(pilotEstimate, "credit_discount_usd"))
	state.NetCostUSD = types.Float64Value(tfhelpers.GetFloat64(pilotEstimate, "net_cost_usd"))
	state.TotalCostUSD = types.Float64Value(tfhelpers.GetFloat64(pilotEstimate, "total_cost_usd"))
	state.StripeInvoiceTotalUSD = types.Float64Value(tfhelpers.GetFloat64(stripeRecon, "stripe_invoice_total_usd"))
	state.StripeReconciliationUSD = types.Float64Value(tfhelpers.GetFloat64(stripeRecon, "stripe_reconciliation_usd"))
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(out))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
