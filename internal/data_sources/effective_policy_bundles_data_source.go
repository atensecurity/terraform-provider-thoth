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

var _ datasource.DataSource = &effectivePolicyBundlesDataSource{}

type effectivePolicyBundlesDataSource struct {
	client *client.Client
}

type effectivePolicyBundlesModel struct {
	AgentID   types.String `tfsdk:"agent_id"`
	Framework types.String `tfsdk:"framework"`
	Total     types.Int64  `tfsdk:"total"`
	DataJSON  types.String `tfsdk:"data_json"`
}

func NewEffectivePolicyBundlesDataSource() datasource.DataSource {
	return &effectivePolicyBundlesDataSource{}
}

func (d *effectivePolicyBundlesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_effective_policy_bundles"
}

func (d *effectivePolicyBundlesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads effective active policy bundles for one agent scope.",
		Attributes: map[string]schema.Attribute{
			"agent_id":  schema.StringAttribute{Optional: true, Description: "Optional agent identity filter."},
			"framework": schema.StringAttribute{Optional: true, Description: "Optional framework filter (OPA or CEDAR)."},
			"total":     schema.Int64Attribute{Computed: true, Description: "Total effective bundles returned."},
			"data_json": schema.StringAttribute{Computed: true, Description: "Effective bundle rows as JSON array."},
		},
	}
}

func (d *effectivePolicyBundlesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *effectivePolicyBundlesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state effectivePolicyBundlesModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	setQueryString(query, "agent_id", state.AgentID)
	setQueryString(query, "framework", state.Framework)

	result, err := d.client.ListEffectivePolicyBundles(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading effective policy bundles", err.Error())
		return
	}

	state.Total = types.Int64Value(tfhelpers.GetInt64(result, "total"))
	if data, ok := result["data"]; ok {
		state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(data))
	} else {
		state.DataJSON = types.StringValue("[]")
	}

	if v := strings.TrimSpace(tfhelpers.GetString(result, "agent_id")); v != "" {
		state.AgentID = types.StringValue(v)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
