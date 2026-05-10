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

var _ datasource.DataSource = &browserEnrollmentsDataSource{}

type browserEnrollmentsDataSource struct {
	client *client.Client
}

type browserEnrollmentsModel struct {
	ProviderName types.String `tfsdk:"provider_name"`
	Status       types.String `tfsdk:"status"`
	Total        types.Int64  `tfsdk:"total"`
	DataJSON     types.String `tfsdk:"data_json"`
}

func NewBrowserEnrollmentsDataSource() datasource.DataSource {
	return &browserEnrollmentsDataSource{}
}

func (d *browserEnrollmentsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_browser_enrollments"
}

func (d *browserEnrollmentsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads browser enrollments with optional provider and status filters.",
		Attributes: map[string]schema.Attribute{
			"provider_name": schema.StringAttribute{
				Optional:    true,
				Description: "Optional browser provider filter.",
			},
			"status": schema.StringAttribute{
				Optional:    true,
				Description: "Optional enrollment status filter.",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total enrollments returned.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Browser enrollment rows as JSON array.",
			},
		},
	}
}

func (d *browserEnrollmentsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *browserEnrollmentsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state browserEnrollmentsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	provider := strings.TrimSpace(state.ProviderName.ValueString())
	status := strings.TrimSpace(state.Status.ValueString())
	rows, err := d.client.ListBrowserEnrollments(ctx, provider, status)
	if err != nil {
		resp.Diagnostics.AddError("Error reading browser enrollments", err.Error())
		return
	}

	if provider == "" {
		state.ProviderName = types.StringNull()
	} else {
		state.ProviderName = types.StringValue(provider)
	}
	if status == "" {
		state.Status = types.StringNull()
	} else {
		state.Status = types.StringValue(status)
	}
	state.Total = types.Int64Value(int64(len(rows)))
	state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(rows))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
