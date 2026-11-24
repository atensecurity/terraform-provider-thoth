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

var _ datasource.DataSource = &toolInventoryDataSource{}

type toolInventoryDataSource struct {
	client *client.Client
}

type toolInventoryModel struct {
	Server                   types.String `tfsdk:"server"`
	NeedsClassification      types.Bool   `tfsdk:"needs_classification"`
	Total                    types.Int64  `tfsdk:"total"`
	RecommendationsAvailable types.Bool   `tfsdk:"recommendations_available"`
	Note                     types.String `tfsdk:"note"`
	DataJSON                 types.String `tfsdk:"data_json"`
}

func NewToolInventoryDataSource() datasource.DataSource {
	return &toolInventoryDataSource{}
}

func (d *toolInventoryDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tool_inventory"
}

func (d *toolInventoryDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The workspace's tools with Thoth's advisory recommendation for each: risk flags, a risk level, suggested action classes, a suggested decision (STEP_UP or BLOCK; ALLOW only for a tool an admin declared read), the reasons, and a draft policy rule. It recommends from names, schemas and observed decisions, which are untrusted; it writes no class, rule or decision. Declare classes with thoth_tool_classification and commit rules through the previewed policy flow. Recommendations need an admin credential.",
		Attributes: map[string]schema.Attribute{
			"server": schema.StringAttribute{
				Optional:    true,
				Description: "Only tools whose name is mcp__<server>__<tool> for this server.",
			},
			"needs_classification": schema.BoolAttribute{
				Optional:    true,
				Description: "True: only tools with no declared class yet. False: only declared tools. Unset: all.",
			},
			"total":                     schema.Int64Attribute{Computed: true, Description: "Number of tools returned."},
			"recommendations_available": schema.BoolAttribute{Computed: true, Description: "False when the credential is not an admin's, so tools carry no recommendation."},
			"note":                      schema.StringAttribute{Computed: true, Description: "The server's note on what the recommendations are."},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Tools as a JSON array of {tool_name, source, agent_ids, first_seen, last_seen, confirmation_status, confirmed_classes, proposed_classes, observed, recommendation}. A tool's reported description, input schema and annotations are left out, since a tool author wrote them.",
			},
		},
	}
}

func (d *toolInventoryDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *toolInventoryDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state toolInventoryModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := d.client.GetToolInventory(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading the tool inventory", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, toolInventoryState(state, result))...)
}

// inventoryFields are the only fields kept from an inventory row. The
// description, input schema and annotations are written by a tool's author:
// they stay out of state and out of any prompt that reads it.
var inventoryFields = []string{
	"tool_name", "source", "agent_ids", "first_seen", "last_seen", "confirmation_status",
	"confirmed_classes", "proposed_classes", "observed", "recommendation",
}

func toolInventoryState(state toolInventoryModel, result map[string]any) *toolInventoryModel {
	server := strings.TrimSpace(state.Server.ValueString())
	rows := []any{}
	available := false
	items, _ := result["items"].([]any)
	for _, raw := range items {
		row, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		recommendation := tfhelpers.GetMap(row, "recommendation")
		if len(recommendation) > 0 {
			available = true
		}
		if server != "" && tfhelpers.GetString(recommendation, "server") != server {
			continue
		}
		if !state.NeedsClassification.IsNull() && !state.NeedsClassification.IsUnknown() {
			needs := tfhelpers.GetString(row, "confirmation_status") != "confirmed"
			if v, ok := recommendation["needs_classification"].(bool); ok {
				needs = v
			}
			if needs != state.NeedsClassification.ValueBool() {
				continue
			}
		}
		kept := map[string]any{}
		for _, field := range inventoryFields {
			if v, ok := row[field]; ok {
				kept[field] = v
			}
		}
		rows = append(rows, kept)
	}
	state.Total = types.Int64Value(int64(len(rows)))
	state.RecommendationsAvailable = types.BoolValue(available)
	state.Note = nullableString(result, "recommendations_note")
	state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(rows))
	return &state
}
