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

var _ datasource.DataSource = &apiKeysDataSource{}

type apiKeysDataSource struct {
	client *client.Client
}

type apiKeysModel struct {
	ScopeLevel    types.String `tfsdk:"scope_level"`
	ScopeTargetID types.String `tfsdk:"scope_target_id"`
	ActiveOnly    types.Bool   `tfsdk:"active_only"`
	Total         types.Int64  `tfsdk:"total"`
	DataJSON      types.String `tfsdk:"data_json"`
}

func NewAPIKeysDataSource() datasource.DataSource {
	return &apiKeysDataSource{}
}

func (d *apiKeysDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_keys"
}

func (d *apiKeysDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads API keys with optional scope and active filters.",
		Attributes: map[string]schema.Attribute{
			"scope_level": schema.StringAttribute{
				Optional:    true,
				Description: "Optional scope filter (organization, fleet, endpoint, agent).",
			},
			"scope_target_id": schema.StringAttribute{
				Optional:    true,
				Description: "Optional scope target ID filter.",
			},
			"active_only": schema.BoolAttribute{
				Optional:    true,
				Description: "When true, only active keys are returned.",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total API keys returned after filtering.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "API key rows as JSON array.",
			},
		},
	}
}

func (d *apiKeysDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *apiKeysDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state apiKeysModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rows, err := d.client.ListAPIKeys(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading API keys", err.Error())
		return
	}

	scopeLevel := strings.TrimSpace(state.ScopeLevel.ValueString())
	scopeTargetID := strings.TrimSpace(state.ScopeTargetID.ValueString())
	activeOnly := !state.ActiveOnly.IsNull() && !state.ActiveOnly.IsUnknown() && state.ActiveOnly.ValueBool()

	filtered := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if scopeLevel != "" && !strings.EqualFold(strings.TrimSpace(tfhelpers.GetString(row, "scope_level")), scopeLevel) {
			continue
		}
		if scopeTargetID != "" && strings.TrimSpace(tfhelpers.GetString(row, "scope_target_id")) != scopeTargetID {
			continue
		}
		if activeOnly && !tfhelpers.GetBool(row, "active") {
			continue
		}
		filtered = append(filtered, row)
	}

	if scopeLevel == "" {
		state.ScopeLevel = types.StringNull()
	} else {
		state.ScopeLevel = types.StringValue(scopeLevel)
	}
	if scopeTargetID == "" {
		state.ScopeTargetID = types.StringNull()
	} else {
		state.ScopeTargetID = types.StringValue(scopeTargetID)
	}
	if state.ActiveOnly.IsNull() || state.ActiveOnly.IsUnknown() {
		state.ActiveOnly = types.BoolNull()
	} else {
		state.ActiveOnly = types.BoolValue(activeOnly)
	}
	state.Total = types.Int64Value(int64(len(filtered)))
	state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(filtered))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
