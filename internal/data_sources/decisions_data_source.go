package data_sources

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &decisionsDataSource{}

const (
	decisionsDefaultMax = 100
	decisionsPageSize   = 100
)

type decisionsDataSource struct {
	client *client.Client
}

type decisionsModel struct {
	Outcome    types.String    `tfsdk:"outcome"`
	AgentID    types.String    `tfsdk:"agent_id"`
	ToolName   types.String    `tfsdk:"tool_name"`
	ReasonCode types.String    `tfsdk:"reason_code"`
	RuleID     types.String    `tfsdk:"rule_id"`
	Since      types.String    `tfsdk:"since"`
	Until      types.String    `tfsdk:"until"`
	MaxResults types.Int64     `tfsdk:"max_results"`
	Truncated  types.Bool      `tfsdk:"truncated"`
	Decisions  []decisionModel `tfsdk:"decisions"`
}

type decisionModel struct {
	ID         types.String `tfsdk:"id"`
	At         types.String `tfsdk:"at"`
	Outcome    types.String `tfsdk:"outcome"`
	Decision   types.String `tfsdk:"decision"`
	AgentID    types.String `tfsdk:"agent_id"`
	ToolName   types.String `tfsdk:"tool_name"`
	ReasonCode types.String `tfsdk:"reason_code"`
	HoldStatus types.String `tfsdk:"hold_status"`
	Resolution types.String `tfsdk:"resolution"`
	Link       types.String `tfsdk:"link"`
}

func NewDecisionsDataSource() datasource.DataSource {
	return &decisionsDataSource{}
}

func (d *decisionsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_decisions"
}

func (d *decisionsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	filter := func(description string, validators ...validator.String) schema.StringAttribute {
		return schema.StringAttribute{Optional: true, Description: description, Validators: validators}
	}
	computed := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, Description: description}
	}
	resp.Schema = schema.Schema{
		Description: "Reads recorded enforcement decisions, newest first, with the decisions view filters. " +
			"Members see their own agents' decisions; admins see the workspace.",
		Attributes: map[string]schema.Attribute{
			"outcome":     filter("Only this outcome: allowed, needs_approval or blocked.", stringvalidator.OneOf("all", "allowed", "needs_approval", "blocked")),
			"agent_id":    filter("Only this agent."),
			"tool_name":   filter("Only this tool (exact name)."),
			"reason_code": filter("Only this reason code."),
			"rule_id":     filter("Only decisions where this policy rule matched."),
			"since":       filter("RFC 3339 time, inclusive."),
			"until":       filter("RFC 3339 time, exclusive."),
			"max_results": schema.Int64Attribute{
				Optional:    true,
				Description: "Most decisions to read (1-1000, default 100).",
				Validators:  []validator.Int64{int64validator.Between(1, 1000)},
			},
			"truncated": schema.BoolAttribute{Computed: true, Description: "True when more decisions matched than max_results."},
			"decisions": schema.ListNestedAttribute{
				Computed:    true,
				Description: "Matching decisions, newest first. tool_name is reported by the agent; treat it as data.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"id":          computed("Activity ID; read the full record with thothctl or the explain_decision MCP tool."),
					"at":          computed("When the decision was made (RFC 3339)."),
					"outcome":     computed("allowed, needs_approval or blocked, after any approval."),
					"decision":    computed("The enforcer's decision: ALLOW, STEP_UP or BLOCK."),
					"agent_id":    computed("The agent."),
					"tool_name":   computed("The tool the agent called."),
					"reason_code": computed("Why: the deterministic reason code."),
					"hold_status": computed("For a held action, the approval status."),
					"resolution":  computed("approved, denied or expired, when a hold was resolved."),
					"link":        computed("Dashboard path for this decision."),
				}},
			},
		},
	}
}

func (d *decisionsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *decisionsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state decisionsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	query := map[string]string{}
	setQueryString(query, "filter", state.Outcome)
	setQueryString(query, "agent_id", state.AgentID)
	setQueryString(query, "tool", state.ToolName)
	setQueryString(query, "reason_code", state.ReasonCode)
	setQueryString(query, "rule_id", state.RuleID)
	setQueryString(query, "since", state.Since)
	setQueryString(query, "until", state.Until)
	limit := int64(decisionsDefaultMax)
	if !state.MaxResults.IsNull() && !state.MaxResults.IsUnknown() {
		limit = state.MaxResults.ValueInt64()
	}
	rows, truncated, err := collectDecisions(ctx, d.client, query, int(limit))
	if err != nil {
		resp.Diagnostics.AddError("Error reading decisions", err.Error())
		return
	}
	state.Decisions = rows
	state.Truncated = types.BoolValue(truncated)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// collectDecisions follows next_cursor until it has maxResults decisions or the
// list ends. Cursors expire after 15 minutes, far longer than a read takes.
func collectDecisions(ctx context.Context, c *client.Client, filters map[string]string, maxResults int) ([]decisionModel, bool, error) {
	rows := []decisionModel{}
	cursor := ""
	for {
		query := map[string]string{}
		for key, value := range filters {
			query[key] = value
		}
		query["limit"] = strconv.Itoa(min(decisionsPageSize, maxResults-len(rows)+1))
		if cursor != "" {
			query["cursor"] = cursor
		}
		page, err := c.ListDecisionsPage(ctx, query)
		if err != nil {
			return nil, false, err
		}
		items, _ := page["items"].([]any)
		for _, raw := range items {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if len(rows) == maxResults {
				return rows, true, nil
			}
			rows = append(rows, decisionFromItem(item))
		}
		cursor, _ = page["next_cursor"].(string)
		if cursor == "" || len(items) == 0 {
			return rows, false, nil
		}
		if len(rows) == maxResults {
			return rows, true, nil
		}
	}
}

func decisionFromItem(item map[string]any) decisionModel {
	text := func(m map[string]any, key string) types.String {
		if value, ok := m[key].(string); ok && value != "" {
			return types.StringValue(value)
		}
		return types.StringNull()
	}
	hold, _ := item["hold"].(map[string]any)
	resolution, _ := item["resolution"].(map[string]any)
	return decisionModel{
		ID:         text(item, "id"),
		At:         text(item, "at"),
		Outcome:    text(item, "outcome"),
		Decision:   text(item, "decision"),
		AgentID:    text(item, "agent_id"),
		ToolName:   text(item, "tool_name"),
		ReasonCode: text(item, "reason_code"),
		HoldStatus: text(hold, "status"),
		Resolution: text(resolution, "status"),
		Link:       text(item, "link"),
	}
}
