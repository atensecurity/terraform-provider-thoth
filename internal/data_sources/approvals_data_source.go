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

var _ datasource.DataSource = &approvalsDataSource{}

type approvalsDataSource struct {
	client *client.Client
}

type approvalsModel struct {
	Status   types.String `tfsdk:"status"`
	Page     types.Int64  `tfsdk:"page"`
	PerPage  types.Int64  `tfsdk:"per_page"`
	Total    types.Int64  `tfsdk:"total"`
	DataJSON types.String `tfsdk:"data_json"`
}

func NewApprovalsDataSource() datasource.DataSource {
	return &approvalsDataSource{}
}

func (d *approvalsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_approvals"
}

func (d *approvalsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads approval queue records with optional status and pagination filters.",
		Attributes: map[string]schema.Attribute{
			"status": schema.StringAttribute{
				Optional:    true,
				Description: "Filter by approval status (pending, approved, denied).",
			},
			"page": schema.Int64Attribute{
				Optional:    true,
				Description: "Page number (1-based).",
			},
			"per_page": schema.Int64Attribute{
				Optional:    true,
				Description: "Items per page.",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total matching approvals.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Approval rows as JSON array.",
			},
		},
	}
}

func (d *approvalsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *approvalsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state approvalsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	setQueryString(query, "status", state.Status)
	if !state.Page.IsNull() && !state.Page.IsUnknown() {
		query["page"] = strconv.FormatInt(state.Page.ValueInt64(), 10)
	}
	if !state.PerPage.IsNull() && !state.PerPage.IsUnknown() {
		query["per_page"] = strconv.FormatInt(state.PerPage.ValueInt64(), 10)
	}

	result, err := d.client.ListApprovalsWithQuery(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading approvals", err.Error())
		return
	}

	state.Total = types.Int64Value(tfhelpers.GetInt64(result, "total"))
	if data, ok := result["data"]; ok {
		state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(data))
	} else {
		state.DataJSON = types.StringValue("[]")
	}
	if v := tfhelpers.GetInt64(result, "page"); v > 0 {
		state.Page = types.Int64Value(v)
	}
	if v := tfhelpers.GetInt64(result, "per_page"); v > 0 {
		state.PerPage = types.Int64Value(v)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
