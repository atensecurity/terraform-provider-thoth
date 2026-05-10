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

var _ datasource.DataSource = &governancePackRuleVersionsDataSource{}

type governancePackRuleVersionsDataSource struct {
	client *client.Client
}

type governancePackRuleVersionsModel struct {
	PackID       types.String `tfsdk:"pack_id"`
	Total        types.Int64  `tfsdk:"total"`
	VersionsJSON types.String `tfsdk:"versions_json"`
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewGovernancePackRuleVersionsDataSource() datasource.DataSource {
	return &governancePackRuleVersionsDataSource{}
}

func (d *governancePackRuleVersionsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_pack_rule_versions"
}

func (d *governancePackRuleVersionsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads all stored rule versions for one compliance pack.",
		Attributes: map[string]schema.Attribute{
			"pack_id": schema.StringAttribute{
				Required:    true,
				Description: "Pack identifier.",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total rule versions returned.",
			},
			"versions_json": schema.StringAttribute{
				Computed:    true,
				Description: "Rule versions array as JSON.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full API response payload as JSON.",
			},
		},
	}
}

func (d *governancePackRuleVersionsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governancePackRuleVersionsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state governancePackRuleVersionsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	packID := strings.TrimSpace(state.PackID.ValueString())
	if packID == "" {
		resp.Diagnostics.AddError("Missing pack_id", "pack_id must be non-empty")
		return
	}

	result, err := d.client.ListGovernancePackRuleVersions(ctx, packID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance pack rule versions", err.Error())
		return
	}

	state.PackID = types.StringValue(packID)
	state.Total = types.Int64Value(tfhelpers.GetInt64(result, "total"))
	if versions, ok := result["versions"]; ok {
		state.VersionsJSON = types.StringValue(tfhelpers.ToJSONArrayString(versions))
	} else {
		state.VersionsJSON = types.StringValue("[]")
	}
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
