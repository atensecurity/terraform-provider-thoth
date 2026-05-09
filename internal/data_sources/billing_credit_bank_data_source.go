package data_sources

import (
	"context"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &billingCreditBankDataSource{}

type billingCreditBankDataSource struct {
	client *client.Client
}

type billingCreditBankModel struct {
	AsOf                    types.String `tfsdk:"as_of"`
	AverageMonthlyBurnCents types.Int64  `tfsdk:"average_monthly_burn_cents"`

	TotalActiveBalanceCents  types.Int64  `tfsdk:"total_active_balance_cents"`
	ActiveWalletCount        types.Int64  `tfsdk:"active_wallet_count"`
	LowBalanceThresholdCents types.Int64  `tfsdk:"low_balance_threshold_cents"`
	LowBalanceAlert          types.Bool   `tfsdk:"low_balance_alert"`
	ActiveWalletsJSON        types.String `tfsdk:"active_wallets_json"`
	ResponseJSON             types.String `tfsdk:"response_json"`
}

func NewBillingCreditBankDataSource() datasource.DataSource {
	return &billingCreditBankDataSource{}
}

func (d *billingCreditBankDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_billing_credit_bank"
}

func (d *billingCreditBankDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads active prepaid credit-bank balances and low-balance alert status.",
		Attributes: map[string]schema.Attribute{
			"as_of": schema.StringAttribute{
				Optional:    true,
				Description: "RFC3339 timestamp used for active wallet filtering. Defaults to now.",
			},
			"average_monthly_burn_cents": schema.Int64Attribute{
				Optional:    true,
				Description: "Optional burn baseline used to compute 20% low-balance threshold.",
			},
			"total_active_balance_cents": schema.Int64Attribute{
				Computed:    true,
				Description: "Total active credit balance across non-expired wallets.",
			},
			"active_wallet_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of active wallets included in this snapshot.",
			},
			"low_balance_threshold_cents": schema.Int64Attribute{
				Computed:    true,
				Description: "Computed low-balance threshold (20% of average monthly burn when provided).",
			},
			"low_balance_alert": schema.BoolAttribute{
				Computed:    true,
				Description: "True when active credit balance is below low-balance threshold.",
			},
			"active_wallets_json": schema.StringAttribute{
				Computed:    true,
				Description: "Active wallets array as JSON.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full credit bank response payload as JSON.",
			},
		},
	}
}

func (d *billingCreditBankDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *billingCreditBankDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state billingCreditBankModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	if !state.AsOf.IsNull() && !state.AsOf.IsUnknown() {
		asOf := strings.TrimSpace(state.AsOf.ValueString())
		if asOf != "" {
			query["as_of"] = asOf
		}
	}
	if !state.AverageMonthlyBurnCents.IsNull() &&
		!state.AverageMonthlyBurnCents.IsUnknown() &&
		state.AverageMonthlyBurnCents.ValueInt64() >= 0 {
		query["average_monthly_burn_cents"] = strconv.FormatInt(state.AverageMonthlyBurnCents.ValueInt64(), 10)
	}

	result, err := d.client.GetBillingCreditBank(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading billing credit bank", err.Error())
		return
	}

	state.TotalActiveBalanceCents = types.Int64Value(tfhelpers.GetInt64(result, "total_active_balance_cents"))
	state.ActiveWalletCount = types.Int64Value(tfhelpers.GetInt64(result, "active_wallet_count"))
	state.LowBalanceThresholdCents = types.Int64Value(tfhelpers.GetInt64(result, "low_balance_threshold_cents"))
	state.LowBalanceAlert = types.BoolValue(tfhelpers.GetBool(result, "low_balance_alert"))
	if raw, ok := result["active_wallets"]; ok {
		state.ActiveWalletsJSON = types.StringValue(tfhelpers.ToJSONArrayString(raw))
	} else {
		state.ActiveWalletsJSON = types.StringValue("[]")
	}
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
