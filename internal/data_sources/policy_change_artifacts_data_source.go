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

var _ datasource.DataSource = &policyChangeArtifactsDataSource{}

type policyChangeArtifactsDataSource struct {
	client *client.Client
}

type policyChangeArtifactsModel struct {
	TargetEnvironment types.String `tfsdk:"target_environment"`
	Limit             types.Int64  `tfsdk:"limit"`
	Offset            types.Int64  `tfsdk:"offset"`
	Total             types.Int64  `tfsdk:"total"`
	DataJSON          types.String `tfsdk:"data_json"`
}

func NewPolicyChangeArtifactsDataSource() datasource.DataSource {
	return &policyChangeArtifactsDataSource{}
}

func (d *policyChangeArtifactsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_change_artifacts"
}

func (d *policyChangeArtifactsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists policy change artifacts with optional environment filter.",
		Attributes: map[string]schema.Attribute{
			"target_environment": schema.StringAttribute{
				Optional:    true,
				Description: "Filter artifacts by target environment.",
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
				Description: "Total matching artifacts.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Policy change artifacts as JSON array.",
			},
		},
	}
}

func (d *policyChangeArtifactsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *policyChangeArtifactsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state policyChangeArtifactsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	setQueryString(query, "target_environment", state.TargetEnvironment)
	if !state.Limit.IsNull() && !state.Limit.IsUnknown() {
		query["limit"] = strconv.FormatInt(state.Limit.ValueInt64(), 10)
	}
	if !state.Offset.IsNull() && !state.Offset.IsUnknown() {
		query["offset"] = strconv.FormatInt(state.Offset.ValueInt64(), 10)
	}

	result, err := d.client.ListPolicyChangeArtifacts(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy change artifacts", err.Error())
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
