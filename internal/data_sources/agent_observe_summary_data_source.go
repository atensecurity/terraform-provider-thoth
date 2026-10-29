package data_sources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &agentObserveSummaryDataSource{}

type agentObserveSummaryDataSource struct {
	client *client.Client
}

type agentObserveSummaryModel struct {
	AgentID         types.String `tfsdk:"agent_id"`
	Days            types.Int64  `tfsdk:"days"`
	Observed        types.Int64  `tfsdk:"observed"`
	WouldChange     types.Int64  `tfsdk:"would_change"`
	ByDecisionJSON  types.String `tfsdk:"by_decision_json"`
	TopRulesJSON    types.String `tfsdk:"top_rules_json"`
	ExamplesJSON    types.String `tfsdk:"examples_json"`
	Mode            types.String `tfsdk:"mode"`
	ReadyToEnforce  types.Bool   `tfsdk:"ready_to_enforce"`
	ReadinessChecks types.String `tfsdk:"readiness_checks_json"`
	Next            types.String `tfsdk:"next"`
}

func NewAgentObserveSummaryDataSource() datasource.DataSource {
	return &agentObserveSummaryDataSource{}
}

func (d *agentObserveSummaryDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent_observe_summary"
}

func (d *agentObserveSummaryDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "What enforcing would have held or denied for an agent in observe mode, and whether it is ready to enforce. Thoth only recommends: switch with thoth_agent_enforcement.",
		Attributes: map[string]schema.Attribute{
			"agent_id": schema.StringAttribute{Required: true, Description: "Agent ID."},
			"days": schema.Int64Attribute{
				Optional: true, Description: "Days to summarise, 1 to 30 (default 7). Readiness always uses its own fixed windows.",
				Validators: []validator.Int64{int64validator.Between(1, 30)},
			},
			"observed":         schema.Int64Attribute{Computed: true, Description: "Actions evaluated in observe mode in the window."},
			"would_change":     schema.Int64Attribute{Computed: true, Description: "Of those, the actions enforcing would have held or denied."},
			"by_decision_json": schema.StringAttribute{Computed: true, Description: "Counts by the decision enforcing would have made, as a JSON object (BLOCK means deny)."},
			"top_rules_json":   schema.StringAttribute{Computed: true, Description: "The rules behind most would-change decisions, as a JSON array of {key, count}."},
			"examples_json":    schema.StringAttribute{Computed: true, Description: "Recent actions enforcing would have changed, as a JSON array."},
			"mode":             schema.StringAttribute{Computed: true, Description: "The agent's current mode: observe or enforce."},
			"ready_to_enforce": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the agent is in observe and passes every check: at least 7 days observed, at least 50 actions in the last 7 days, at most 2% that would have been held or denied, and nothing that would have been denied in the last 3 days.",
			},
			"readiness_checks_json": schema.StringAttribute{Computed: true, Description: "Each readiness check as a JSON array of {id, passed, detail}."},
			"next":                  schema.StringAttribute{Computed: true, Description: "What to do next, in words."},
		},
	}
}

func (d *agentObserveSummaryDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *agentObserveSummaryDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state agentObserveSummaryModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	agentID := strings.TrimSpace(state.AgentID.ValueString())
	if agentID == "" {
		resp.Diagnostics.AddAttributeError(path.Root("agent_id"), "Missing agent_id", "agent_id must be set.")
		return
	}
	days := int64(0)
	if !state.Days.IsNull() && !state.Days.IsUnknown() {
		days = state.Days.ValueInt64()
	}
	result, err := d.client.GetAgentObserveSummary(ctx, agentID, days)
	if err != nil {
		resp.Diagnostics.AddError("Error reading the observe summary", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, observeSummaryState(state, result))...)
}

func observeSummaryState(state agentObserveSummaryModel, result map[string]any) *agentObserveSummaryModel {
	readiness := tfhelpers.GetMap(result, "readiness")
	ready, _ := readiness["ready"].(bool)
	state.Observed = types.Int64Value(tfhelpers.GetInt64(result, "observed"))
	state.WouldChange = types.Int64Value(tfhelpers.GetInt64(result, "would_change"))
	state.ByDecisionJSON = types.StringValue(tfhelpers.ToJSONString(result["by_decision"]))
	state.TopRulesJSON = types.StringValue(tfhelpers.ToJSONArrayString(result["top_rules"]))
	state.ExamplesJSON = types.StringValue(tfhelpers.ToJSONArrayString(result["examples"]))
	state.Mode = nullableString(readiness, "mode")
	state.ReadyToEnforce = types.BoolValue(ready)
	state.ReadinessChecks = types.StringValue(tfhelpers.ToJSONArrayString(readiness["checks"]))
	state.Next = nullableString(readiness, "next")
	return &state
}
