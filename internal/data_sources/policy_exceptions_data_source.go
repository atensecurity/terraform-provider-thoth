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

var _ datasource.DataSource = &policyExceptionsDataSource{}

type policyExceptionsDataSource struct {
	client *client.Client
}

type policyExceptionsModel struct {
	Status      types.String `tfsdk:"status"`
	RequestedBy types.String `tfsdk:"requested_by"`
	ReviewedBy  types.String `tfsdk:"reviewed_by"`
	Limit       types.Int64  `tfsdk:"limit"`
	Offset      types.Int64  `tfsdk:"offset"`
	Total       types.Int64  `tfsdk:"total"`
	DataJSON    types.String `tfsdk:"data_json"`
}

func NewPolicyExceptionsDataSource() datasource.DataSource {
	return &policyExceptionsDataSource{}
}

func (d *policyExceptionsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_exceptions"
}

func (d *policyExceptionsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists policy exception requests with optional filters.",
		Attributes: map[string]schema.Attribute{
			"status": schema.StringAttribute{
				Optional:    true,
				Description: "Filter by status (pending, under_review, approved, denied, approved_with_modification).",
			},
			"requested_by": schema.StringAttribute{
				Optional:    true,
				Description: "Filter by requester identity.",
			},
			"reviewed_by": schema.StringAttribute{
				Optional:    true,
				Description: "Filter by reviewer identity.",
			},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Max records to return.",
			},
			"offset": schema.Int64Attribute{
				Optional:    true,
				Description: "Pagination offset.",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total matching exception requests.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Policy exception rows as JSON array.",
			},
		},
	}
}

func (d *policyExceptionsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *policyExceptionsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state policyExceptionsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	setQueryString(query, "status", state.Status)
	setQueryString(query, "requested_by", state.RequestedBy)
	setQueryString(query, "reviewed_by", state.ReviewedBy)
	if !state.Limit.IsNull() && !state.Limit.IsUnknown() {
		query["limit"] = strconv.FormatInt(state.Limit.ValueInt64(), 10)
	}
	if !state.Offset.IsNull() && !state.Offset.IsUnknown() {
		query["offset"] = strconv.FormatInt(state.Offset.ValueInt64(), 10)
	}

	result, err := d.client.ListPolicyExceptions(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy exceptions", err.Error())
		return
	}

	state.Total = types.Int64Value(tfhelpers.GetInt64(result, "total"))
	if data, ok := result["data"]; ok {
		state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(data))
	} else {
		state.DataJSON = types.StringValue("[]")
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
