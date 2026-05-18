package data_sources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &agentLatestForensicsDataSource{}

type agentLatestForensicsDataSource struct {
	client *client.Client
}

type agentLatestForensicsModel struct {
	AgentID              types.String `tfsdk:"agent_id"`
	SessionID            types.String `tfsdk:"session_id"`
	AgentName            types.String `tfsdk:"agent_name"`
	RiskScore            types.Int64  `tfsdk:"risk_score"`
	EventsJSON           types.String `tfsdk:"events_json"`
	TelemetrySummaryJSON types.String `tfsdk:"telemetry_summary_json"`
	AttackSurfaceJSON    types.String `tfsdk:"attack_surface_json"`
	ResponseJSON         types.String `tfsdk:"response_json"`
}

func NewAgentLatestForensicsDataSource() datasource.DataSource {
	return &agentLatestForensicsDataSource{}
}

func (d *agentLatestForensicsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent_latest_forensics"
}

func (d *agentLatestForensicsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads the latest known session forensics timeline for one agent.",
		Attributes: map[string]schema.Attribute{
			"agent_id": schema.StringAttribute{
				Required:    true,
				Description: "Agent identifier.",
			},
			"session_id": schema.StringAttribute{
				Computed:    true,
				Description: "Latest resolved session ID for this agent.",
			},
			"agent_name": schema.StringAttribute{
				Computed:    true,
				Description: "Agent name associated with the resolved session.",
			},
			"risk_score": schema.Int64Attribute{
				Computed:    true,
				Description: "Aggregated session risk score.",
			},
			"events_json": schema.StringAttribute{
				Computed:    true,
				Description: "Ordered forensics events array as JSON.",
			},
			"telemetry_summary_json": schema.StringAttribute{
				Computed:    true,
				Description: "Session telemetry summary object as JSON.",
			},
			"attack_surface_json": schema.StringAttribute{
				Computed:    true,
				Description: "Derived attack-surface summary object as JSON.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full agent latest forensics response payload as JSON.",
			},
		},
	}
}

func (d *agentLatestForensicsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *agentLatestForensicsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state agentLatestForensicsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	agentID := strings.TrimSpace(state.AgentID.ValueString())
	if agentID == "" {
		resp.Diagnostics.AddAttributeError(path.Root("agent_id"), "Missing agent_id", "agent_id must be set.")
		return
	}
	state.AgentID = types.StringValue(agentID)

	result, err := d.client.GetAgentLatestForensics(ctx, agentID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading agent latest forensics", err.Error())
		return
	}

	state.SessionID = nullableString(result, "session_id")
	state.AgentName = nullableString(result, "agent_name")
	state.RiskScore = types.Int64Value(tfhelpers.GetInt64(result, "risk_score"))

	if events, ok := result["events"]; ok {
		state.EventsJSON = types.StringValue(tfhelpers.ToJSONArrayString(events))
	} else {
		state.EventsJSON = types.StringValue("[]")
	}
	if telemetry, ok := result["telemetry_summary"]; ok {
		state.TelemetrySummaryJSON = types.StringValue(tfhelpers.ToJSONString(telemetry))
	} else {
		state.TelemetrySummaryJSON = types.StringValue("{}")
	}
	if surface, ok := result["attack_surface"]; ok {
		state.AttackSurfaceJSON = types.StringValue(tfhelpers.ToJSONString(surface))
	} else {
		state.AttackSurfaceJSON = types.StringValue("{}")
	}
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
