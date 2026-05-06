package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &governanceRuntimeStatusDataSource{}

type governanceRuntimeStatusDataSource struct {
	client *client.Client
}

type governanceRuntimeStatusModel struct {
	Environment  types.String `tfsdk:"environment"`
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewGovernanceRuntimeStatusDataSource() datasource.DataSource {
	return &governanceRuntimeStatusDataSource{}
}

func (d *governanceRuntimeStatusDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_runtime_status"
}

func (d *governanceRuntimeStatusDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads pack runtime status and drift summary for governance enforcement.",
		Attributes: map[string]schema.Attribute{
			"environment": schema.StringAttribute{
				Optional:    true,
				Description: "Optional environment filter (dev or prod).",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Runtime status payload as JSON.",
			},
		},
	}
}

func (d *governanceRuntimeStatusDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governanceRuntimeStatusDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state governanceRuntimeStatusModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	setQueryString(query, "env", state.Environment)

	result, err := d.client.GetPackRuntimeStatus(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance runtime status", err.Error())
		return
	}

	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
