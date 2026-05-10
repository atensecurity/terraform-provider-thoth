package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &policyBundlesDataSource{}

type policyBundlesDataSource struct {
	client *client.Client
}

type policyBundlesModel struct {
	Framework       types.String `tfsdk:"framework"`
	Status          types.String `tfsdk:"status"`
	EnforcementMode types.String `tfsdk:"enforcement_mode"`
	Assignment      types.String `tfsdk:"assignment"`
	Total           types.Int64  `tfsdk:"total"`
	DataJSON        types.String `tfsdk:"data_json"`
}

func NewPolicyBundlesDataSource() datasource.DataSource {
	return &policyBundlesDataSource{}
}

func (d *policyBundlesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_bundles"
}

func (d *policyBundlesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads versioned OPA/Cedar policy bundles for the tenant.",
		Attributes: map[string]schema.Attribute{
			"framework": schema.StringAttribute{Optional: true, Description: "Framework filter (OPA or CEDAR)."},
			"status":    schema.StringAttribute{Optional: true, Description: "Status filter (active, staged, paused, disabled)."},
			"enforcement_mode": schema.StringAttribute{
				Optional:    true,
				Description: "Mode filter (enforce or observe).",
			},
			"assignment": schema.StringAttribute{Optional: true, Description: "Assignment filter (for example: all, agent:security-analyst-agent, coding-agent)."},
			"total":      schema.Int64Attribute{Computed: true, Description: "Total bundles returned."},
			"data_json":  schema.StringAttribute{Computed: true, Description: "Bundle rows as JSON array."},
		},
	}
}

func (d *policyBundlesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *policyBundlesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state policyBundlesModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	setQueryString(query, "framework", state.Framework)
	setQueryString(query, "status", state.Status)
	setQueryString(query, "enforcement_mode", state.EnforcementMode)
	setQueryString(query, "assignment", state.Assignment)

	result, err := d.client.ListPolicyBundles(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy bundles", err.Error())
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
