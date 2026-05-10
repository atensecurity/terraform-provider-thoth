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

var _ datasource.DataSource = &governancePackRulesDataSource{}

type governancePackRulesDataSource struct {
	client *client.Client
}

type governancePackRulesModel struct {
	PackID             types.String `tfsdk:"pack_id"`
	Regulation         types.String `tfsdk:"regulation"`
	DisplayName        types.String `tfsdk:"display_name"`
	BasePackVersion    types.String `tfsdk:"base_pack_version"`
	TotalVersions      types.Int64  `tfsdk:"total_versions"`
	CurrentVersionJSON types.String `tfsdk:"current_version_json"`
	ResponseJSON       types.String `tfsdk:"response_json"`
}

func NewGovernancePackRulesDataSource() datasource.DataSource {
	return &governancePackRulesDataSource{}
}

func (d *governancePackRulesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_pack_rules"
}

func (d *governancePackRulesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads the active rule version payload for one compliance pack.",
		Attributes: map[string]schema.Attribute{
			"pack_id": schema.StringAttribute{
				Required:    true,
				Description: "Pack identifier.",
			},
			"regulation": schema.StringAttribute{
				Computed:    true,
				Description: "Regulation group for this pack.",
			},
			"display_name": schema.StringAttribute{
				Computed:    true,
				Description: "Human-readable pack name.",
			},
			"base_pack_version": schema.StringAttribute{
				Computed:    true,
				Description: "Base pack version associated with the active custom rule set.",
			},
			"total_versions": schema.Int64Attribute{
				Computed:    true,
				Description: "Total rule versions retained for this pack.",
			},
			"current_version_json": schema.StringAttribute{
				Computed:    true,
				Description: "Active rule version payload as JSON.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full API response payload as JSON.",
			},
		},
	}
}

func (d *governancePackRulesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governancePackRulesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state governancePackRulesModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	packID := strings.TrimSpace(state.PackID.ValueString())
	if packID == "" {
		resp.Diagnostics.AddError("Missing pack_id", "pack_id must be non-empty")
		return
	}

	result, err := d.client.GetGovernancePackRules(ctx, packID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance pack rules", err.Error())
		return
	}

	state.PackID = types.StringValue(packID)
	state.Regulation = nullableString(result, "regulation")
	state.DisplayName = nullableString(result, "display_name")
	state.BasePackVersion = nullableString(result, "base_pack_version")
	state.TotalVersions = types.Int64Value(tfhelpers.GetInt64(result, "total_versions"))
	if current, ok := result["current_version"]; ok {
		state.CurrentVersionJSON = types.StringValue(tfhelpers.ToJSONString(current))
	} else {
		state.CurrentVersionJSON = types.StringValue("{}")
	}
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
