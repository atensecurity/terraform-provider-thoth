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

var _ datasource.DataSource = &billingInvoicesDataSource{}

type billingInvoicesDataSource struct {
	client *client.Client
}

type billingInvoicesModel struct {
	Limit        types.Int64  `tfsdk:"limit"`
	Total        types.Int64  `tfsdk:"total"`
	InvoicesJSON types.String `tfsdk:"invoices_json"`
	TotalsJSON   types.String `tfsdk:"totals_json"`
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewBillingInvoicesDataSource() datasource.DataSource {
	return &billingInvoicesDataSource{}
}

func (d *billingInvoicesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_billing_invoices"
}

func (d *billingInvoicesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads recent billing invoices and totals for the tenant.",
		Attributes: map[string]schema.Attribute{
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of invoices to return.",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total invoices returned.",
			},
			"invoices_json": schema.StringAttribute{
				Computed:    true,
				Description: "Invoice rows as JSON array.",
			},
			"totals_json": schema.StringAttribute{
				Computed:    true,
				Description: "Invoice aggregate totals object as JSON.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full billing invoices response payload as JSON.",
			},
		},
	}
}

func (d *billingInvoicesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *billingInvoicesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state billingInvoicesModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	if !state.Limit.IsNull() && !state.Limit.IsUnknown() && state.Limit.ValueInt64() > 0 {
		query["limit"] = strconv.FormatInt(state.Limit.ValueInt64(), 10)
	}

	result, err := d.client.ListBillingInvoices(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading billing invoices", err.Error())
		return
	}

	state.Total = types.Int64Value(tfhelpers.GetInt64(result, "count"))
	if raw, ok := result["invoices"]; ok {
		state.InvoicesJSON = types.StringValue(tfhelpers.ToJSONArrayString(raw))
	} else {
		state.InvoicesJSON = types.StringValue("[]")
	}
	if raw, ok := result["totals"]; ok {
		state.TotalsJSON = types.StringValue(tfhelpers.ToJSONString(raw))
	} else {
		state.TotalsJSON = types.StringValue("{}")
	}
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
