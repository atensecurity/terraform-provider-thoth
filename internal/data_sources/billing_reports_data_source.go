package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &billingReportsDataSource{}

type billingReportsDataSource struct {
	client *client.Client
}

type billingReportsModel struct {
	Total        types.Int64  `tfsdk:"total"`
	ReportsJSON  types.String `tfsdk:"reports_json"`
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewBillingReportsDataSource() datasource.DataSource {
	return &billingReportsDataSource{}
}

func (d *billingReportsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_billing_reports"
}

func (d *billingReportsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads billing report summaries for recent closed billing periods.",
		Attributes: map[string]schema.Attribute{
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total report summaries returned.",
			},
			"reports_json": schema.StringAttribute{
				Computed:    true,
				Description: "Billing report summaries as JSON array.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full billing report summary response payload as JSON.",
			},
		},
	}
}

func (d *billingReportsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *billingReportsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state billingReportsModel

	result, err := d.client.ListBillingReports(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading billing reports", err.Error())
		return
	}

	state.Total = types.Int64Value(tfhelpers.GetInt64(result, "count"))
	if raw, ok := result["reports"]; ok {
		state.ReportsJSON = types.StringValue(tfhelpers.ToJSONArrayString(raw))
	} else {
		state.ReportsJSON = types.StringValue("[]")
	}
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
