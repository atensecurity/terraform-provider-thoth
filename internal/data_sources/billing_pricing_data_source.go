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
	ActiveTier                  types.String  `tfsdk:"active_tier"`
	BaseMonthlyPlatformFeeUSD   types.Float64 `tfsdk:"base_monthly_platform_fee_usd"`
	IncludedGovernedIdentities  types.Int64   `tfsdk:"included_governed_identities"`
	IncludedPolicyChecks        types.Int64   `tfsdk:"included_policy_checks"`
	GovernedIdentityUSDPerMonth types.Float64 `tfsdk:"governed_identity_usd_per_month"`
	PolicyChecksUSDPerMillion   types.Float64 `tfsdk:"policy_checks_usd_per_million"`
	PrepaidCreditUSD            types.Float64 `tfsdk:"prepaid_credit_usd"`
	CreditDiscountPercent       types.Float64 `tfsdk:"credit_discount_percent"`
	OverageCapUSD               types.Float64 `tfsdk:"overage_cap_usd"`
	CatalogVersion              types.String  `tfsdk:"catalog_version"`
	ResponseJSON                types.String  `tfsdk:"response_json"`
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
			"active_tier": schema.StringAttribute{
				Computed:    true,
				Description: "Effective active pricing tier used for billing.",
			},
			"base_monthly_platform_fee_usd": schema.Float64Attribute{
				Computed:    true,
				Description: "Base monthly platform fee for the active tier.",
			},
			"included_governed_identities": schema.Int64Attribute{
				Computed:    true,
				Description: "Included governed identities before overage rates apply.",
			},
			"included_policy_checks": schema.Int64Attribute{
				Computed:    true,
				Description: "Included policy checks before overage rates apply.",
			},
			"governed_identity_usd_per_month": schema.Float64Attribute{
				Computed:    true,
				Description: "Per-identity overage rate.",
			},
			"policy_checks_usd_per_million": schema.Float64Attribute{
				Computed:    true,
				Description: "Per-million policy checks overage rate.",
			},
			"prepaid_credit_usd": schema.Float64Attribute{
				Computed:    true,
				Description: "Current configured prepaid credit amount.",
			},
			"credit_discount_percent": schema.Float64Attribute{
				Computed:    true,
				Description: "Configured discount percent tied to prepaid credits.",
			},
			"overage_cap_usd": schema.Float64Attribute{
				Computed:    true,
				Description: "Customer-configurable monthly variable overage cap.",
			},
			"catalog_version": schema.StringAttribute{
				Computed:    true,
				Description: "Pricing catalog version used for this profile.",
			},
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
	metered := tfhelpers.GetMap(out, "metered_pricing")
	pilot := tfhelpers.GetMap(out, "pilot_package")
	state.ActiveTier = types.StringValue(tfhelpers.GetString(out, "active_tier"))
	state.BaseMonthlyPlatformFeeUSD = types.Float64Value(tfhelpers.GetFloat64(metered, "base_monthly_platform_fee_usd"))
	state.IncludedGovernedIdentities = types.Int64Value(tfhelpers.GetInt64(metered, "included_governed_identities"))
	state.IncludedPolicyChecks = types.Int64Value(tfhelpers.GetInt64(metered, "included_policy_checks"))
	state.GovernedIdentityUSDPerMonth = types.Float64Value(tfhelpers.GetFloat64(metered, "governed_identity_usd_per_month"))
	state.PolicyChecksUSDPerMillion = types.Float64Value(tfhelpers.GetFloat64(metered, "policy_checks_usd_per_million"))
	state.PrepaidCreditUSD = types.Float64Value(tfhelpers.GetFloat64(metered, "prepaid_credit_usd"))
	state.CreditDiscountPercent = types.Float64Value(tfhelpers.GetFloat64(metered, "credit_discount_percent"))
	state.OverageCapUSD = types.Float64Value(tfhelpers.GetFloat64(pilot, "overage_cap_usd"))
	state.CatalogVersion = types.StringValue(tfhelpers.GetString(out, "catalog_version"))
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(out))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
