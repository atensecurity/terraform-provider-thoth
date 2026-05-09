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

var _ datasource.DataSource = &billingEstimateDataSource{}

type billingEstimateDataSource struct {
	client *client.Client
}

type billingEstimateModel struct {
	Period                   types.String  `tfsdk:"period"`
	AsOf                     types.String  `tfsdk:"as_of"`
	ComplianceUpliftPercent  types.Float64 `tfsdk:"compliance_uplift_percent"`
	FixedDiscountPercent     types.Float64 `tfsdk:"fixed_discount_percent"`
	AverageMonthlyBurnCents  types.Int64   `tfsdk:"average_monthly_burn_cents"`
	ActiveIdentitiesOverride types.Int64   `tfsdk:"active_identities_override"`
	PolicyChecksOverride     types.Int64   `tfsdk:"policy_checks_override"`

	PeriodEffective              types.String `tfsdk:"period_effective"`
	PricingTier                  types.String `tfsdk:"pricing_tier"`
	GrossBillCents               types.Int64  `tfsdk:"gross_bill_cents"`
	NetTotalCents                types.Int64  `tfsdk:"net_total_cents"`
	LineItemPlatformFeeCents     types.Int64  `tfsdk:"line_item_platform_fee_cents"`
	LineItemIdentityOverageCents types.Int64  `tfsdk:"line_item_identity_overage_cents"`
	LineItemEnforcementOverage   types.Int64  `tfsdk:"line_item_enforcement_overage_cents"`
	LineItemStorageCapacity      types.Int64  `tfsdk:"line_item_storage_capacity_cents"`
	LineItemStorageRetention     types.Int64  `tfsdk:"line_item_storage_retention_cents"`
	LineItemComplianceUplift     types.Int64  `tfsdk:"line_item_compliance_uplift_cents"`
	LineItemDiscountCents        types.Int64  `tfsdk:"line_item_fixed_discount_cents"`
	LineItemCreditsAppliedCents  types.Int64  `tfsdk:"line_item_credits_applied_cents"`
	WORMRetentionDays            types.Int64  `tfsdk:"worm_retention_days"`
	ComplianceReceipt            types.String `tfsdk:"compliance_receipt"`
	LowBalanceAlert              types.Bool   `tfsdk:"low_balance_alert"`
	CreditBurnsJSON              types.String `tfsdk:"credit_burns_json"`
	SummaryJSON                  types.String `tfsdk:"summary_json"`
	ResponseJSON                 types.String `tfsdk:"response_json"`
}

func NewBillingEstimateDataSource() datasource.DataSource {
	return &billingEstimateDataSource{}
}

func (d *billingEstimateDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_billing_estimate"
}

func (d *billingEstimateDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Builds a dry-run monthly invoice estimate using Aten-managed pricing, usage, and credit-bank burn-down.",
		Attributes: map[string]schema.Attribute{
			"period": schema.StringAttribute{
				Optional:    true,
				Description: "Billing period in YYYY-MM format. Defaults to current UTC month.",
			},
			"as_of": schema.StringAttribute{
				Optional:    true,
				Description: "RFC3339 timestamp for estimate cutoff.",
			},
			"compliance_uplift_percent": schema.Float64Attribute{
				Optional:    true,
				Description: "Optional compliance surcharge percent applied before discounts.",
			},
			"fixed_discount_percent": schema.Float64Attribute{
				Optional:    true,
				Description: "Optional fixed discount percent applied before credit-bank burn-down.",
			},
			"average_monthly_burn_cents": schema.Int64Attribute{
				Optional:    true,
				Description: "Optional baseline used for low-balance alert threshold.",
			},
			"active_identities_override": schema.Int64Attribute{
				Optional:    true,
				Description: "Optional usage override for active governed identities.",
			},
			"policy_checks_override": schema.Int64Attribute{
				Optional:    true,
				Description: "Optional usage override for policy checks.",
			},
			"period_effective": schema.StringAttribute{
				Computed:    true,
				Description: "Effective billing period used by GovAPI.",
			},
			"pricing_tier": schema.StringAttribute{
				Computed:    true,
				Description: "Effective pricing tier used for estimate calculation.",
			},
			"gross_bill_cents": schema.Int64Attribute{
				Computed:    true,
				Description: "Gross bill before fixed discounts and credit-bank application.",
			},
			"net_total_cents": schema.Int64Attribute{
				Computed:    true,
				Description: "Net bill after discounts and FIFO prepaid-credit burn-down.",
			},
			"line_item_platform_fee_cents": schema.Int64Attribute{
				Computed:    true,
				Description: "Platform fee line item in cents.",
			},
			"line_item_identity_overage_cents": schema.Int64Attribute{
				Computed:    true,
				Description: "Identity overage line item in cents.",
			},
			"line_item_enforcement_overage_cents": schema.Int64Attribute{
				Computed:    true,
				Description: "Enforcement overage line item in cents.",
			},
			"line_item_storage_capacity_cents": schema.Int64Attribute{
				Computed:    true,
				Description: "Storage capacity surcharge line item in cents.",
			},
			"line_item_storage_retention_cents": schema.Int64Attribute{
				Computed:    true,
				Description: "Storage retention surcharge line item in cents.",
			},
			"line_item_compliance_uplift_cents": schema.Int64Attribute{
				Computed:    true,
				Description: "Compliance uplift line item in cents.",
			},
			"line_item_fixed_discount_cents": schema.Int64Attribute{
				Computed:    true,
				Description: "Fixed discount line item in cents.",
			},
			"line_item_credits_applied_cents": schema.Int64Attribute{
				Computed:    true,
				Description: "Credits consumed from active wallets in cents.",
			},
			"worm_retention_days": schema.Int64Attribute{
				Computed:    true,
				Description: "Effective WORM retention days represented in billing output.",
			},
			"compliance_receipt": schema.StringAttribute{
				Computed:    true,
				Description: "Compliance receipt text included in downstream invoices.",
			},
			"low_balance_alert": schema.BoolAttribute{
				Computed:    true,
				Description: "True when active credit balance is below alert threshold.",
			},
			"credit_burns_json": schema.StringAttribute{
				Computed:    true,
				Description: "FIFO wallet burn-down events as JSON.",
			},
			"summary_json": schema.StringAttribute{
				Computed:    true,
				Description: "Nested invoice summary object as JSON.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full estimate payload as JSON.",
			},
		},
	}
}

func (d *billingEstimateDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *billingEstimateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state billingEstimateModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := map[string]any{}
	if !state.Period.IsNull() && !state.Period.IsUnknown() {
		if period := strings.TrimSpace(state.Period.ValueString()); period != "" {
			payload["period"] = period
		}
	}
	if !state.AsOf.IsNull() && !state.AsOf.IsUnknown() {
		if asOf := strings.TrimSpace(state.AsOf.ValueString()); asOf != "" {
			payload["as_of"] = asOf
		}
	}
	if !state.ComplianceUpliftPercent.IsNull() && !state.ComplianceUpliftPercent.IsUnknown() {
		payload["compliance_uplift_percent"] = state.ComplianceUpliftPercent.ValueFloat64()
	}
	if !state.FixedDiscountPercent.IsNull() && !state.FixedDiscountPercent.IsUnknown() {
		payload["fixed_discount_percent"] = state.FixedDiscountPercent.ValueFloat64()
	}
	if !state.AverageMonthlyBurnCents.IsNull() && !state.AverageMonthlyBurnCents.IsUnknown() {
		payload["average_monthly_burn_cents"] = state.AverageMonthlyBurnCents.ValueInt64()
	}
	if !state.ActiveIdentitiesOverride.IsNull() && !state.ActiveIdentitiesOverride.IsUnknown() {
		payload["active_identities_override"] = state.ActiveIdentitiesOverride.ValueInt64()
	}
	if !state.PolicyChecksOverride.IsNull() && !state.PolicyChecksOverride.IsUnknown() {
		payload["policy_checks_override"] = state.PolicyChecksOverride.ValueInt64()
	}

	result, err := d.client.GetBillingEstimate(ctx, payload, nil)
	if err != nil {
		resp.Diagnostics.AddError("Error reading billing estimate", err.Error())
		return
	}
	summary := tfhelpers.GetMap(result, "summary")

	state.PeriodEffective = types.StringValue(tfhelpers.GetString(result, "period"))
	state.PricingTier = types.StringValue(tfhelpers.GetString(result, "pricing_tier"))
	state.GrossBillCents = types.Int64Value(tfhelpers.GetInt64(summary, "gross_bill_cents"))
	state.NetTotalCents = types.Int64Value(tfhelpers.GetInt64(summary, "net_total_cents"))
	state.LineItemPlatformFeeCents = types.Int64Value(tfhelpers.GetInt64(summary, "line_item_platform_fee_cents"))
	state.LineItemIdentityOverageCents = types.Int64Value(tfhelpers.GetInt64(summary, "line_item_identity_overage_cents"))
	state.LineItemEnforcementOverage = types.Int64Value(tfhelpers.GetInt64(summary, "line_item_enforcement_overage_cents"))
	state.LineItemStorageCapacity = types.Int64Value(tfhelpers.GetInt64(summary, "line_item_storage_capacity_cents"))
	state.LineItemStorageRetention = types.Int64Value(tfhelpers.GetInt64(summary, "line_item_storage_retention_cents"))
	state.LineItemComplianceUplift = types.Int64Value(tfhelpers.GetInt64(summary, "line_item_compliance_uplift_cents"))
	state.LineItemDiscountCents = types.Int64Value(tfhelpers.GetInt64(summary, "line_item_fixed_discount_cents"))
	state.LineItemCreditsAppliedCents = types.Int64Value(tfhelpers.GetInt64(summary, "line_item_credits_applied_cents"))
	state.WORMRetentionDays = types.Int64Value(tfhelpers.GetInt64(result, "worm_retention_days"))
	state.ComplianceReceipt = types.StringValue(tfhelpers.GetString(result, "compliance_receipt"))
	state.LowBalanceAlert = types.BoolValue(tfhelpers.GetBool(result, "low_balance_alert"))
	if raw, ok := summary["credit_burns"]; ok {
		state.CreditBurnsJSON = types.StringValue(tfhelpers.ToJSONArrayString(raw))
	} else {
		state.CreditBurnsJSON = types.StringValue("[]")
	}
	state.SummaryJSON = types.StringValue(tfhelpers.ToJSONString(summary))
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
