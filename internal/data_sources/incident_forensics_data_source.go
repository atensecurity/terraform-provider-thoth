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

var _ datasource.DataSource = &incidentForensicsDataSource{}

type incidentForensicsDataSource struct {
	client *client.Client
}

type incidentForensicsModel struct {
	IncidentID           types.String `tfsdk:"incident_id"`
	IncidentSource       types.String `tfsdk:"incident_source"`
	SessionID            types.String `tfsdk:"session_id"`
	AgentID              types.String `tfsdk:"agent_id"`
	AgentName            types.String `tfsdk:"agent_name"`
	RiskScore            types.Int64  `tfsdk:"risk_score"`
	EventsJSON           types.String `tfsdk:"events_json"`
	TelemetrySummaryJSON types.String `tfsdk:"telemetry_summary_json"`
	AttackSurfaceJSON    types.String `tfsdk:"attack_surface_json"`
	ResponseJSON         types.String `tfsdk:"response_json"`
}

func NewIncidentForensicsDataSource() datasource.DataSource {
	return &incidentForensicsDataSource{}
}

func (d *incidentForensicsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_incident_forensics"
}

func (d *incidentForensicsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Resolves an incident ID and returns its full forensics timeline.",
		Attributes: map[string]schema.Attribute{
			"incident_id": schema.StringAttribute{
				Required:    true,
				Description: "Incident identifier.",
			},
			"incident_source": schema.StringAttribute{
				Computed:    true,
				Description: "Incident source subsystem.",
			},
			"session_id": schema.StringAttribute{
				Computed:    true,
				Description: "Resolved session ID for this incident.",
			},
			"agent_id": schema.StringAttribute{
				Computed:    true,
				Description: "Agent identifier associated with the incident session.",
			},
			"agent_name": schema.StringAttribute{
				Computed:    true,
				Description: "Agent name associated with the incident session.",
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
				Description: "Full incident forensics response payload as JSON.",
			},
		},
	}
}

func (d *incidentForensicsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *incidentForensicsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state incidentForensicsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	incidentID := strings.TrimSpace(state.IncidentID.ValueString())
	if incidentID == "" {
		resp.Diagnostics.AddAttributeError(path.Root("incident_id"), "Missing incident_id", "incident_id must be set.")
		return
	}
	state.IncidentID = types.StringValue(incidentID)

	result, err := d.client.GetIncidentForensics(ctx, incidentID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading incident forensics", err.Error())
		return
	}

	state.IncidentSource = nullableString(result, "incident_source")
	state.SessionID = nullableString(result, "session_id")
	state.AgentID = nullableString(result, "agent_id")
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
