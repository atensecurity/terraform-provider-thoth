package data_sources

import (
	"context"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &governanceFeedDataSource{}

type governanceFeedDataSource struct {
	client *client.Client
}

type governanceFeedModel struct {
	Page          types.Int64  `tfsdk:"page"`
	PerPage       types.Int64  `tfsdk:"per_page"`
	AgentID       types.String `tfsdk:"agent_id"`
	CallerAgentID types.String `tfsdk:"caller_agent_id"`
	ToolName      types.String `tfsdk:"tool_name"`
	Decision      types.String `tfsdk:"decision"`
	ReasonCode    types.String `tfsdk:"reason_code"`
	Search        types.String `tfsdk:"search"`
	From          types.String `tfsdk:"from"`
	To            types.String `tfsdk:"to"`
	SortBy        types.String `tfsdk:"sort_by"`
	SortDir       types.String `tfsdk:"sort_dir"`
	Total         types.Int64  `tfsdk:"total"`
	DataJSON      types.String `tfsdk:"data_json"`
}

func NewGovernanceFeedDataSource() datasource.DataSource {
	return &governanceFeedDataSource{}
}

func (d *governanceFeedDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_feed"
}

func (d *governanceFeedDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads normalized governance feed events.",
		Attributes: map[string]schema.Attribute{
			"page":            schema.Int64Attribute{Optional: true, Description: "Page number (1-based)."},
			"per_page":        schema.Int64Attribute{Optional: true, Description: "Items per page."},
			"agent_id":        schema.StringAttribute{Optional: true, Description: "Filter by agent ID."},
			"caller_agent_id": schema.StringAttribute{Optional: true, Description: "Filter by caller agent ID."},
			"tool_name":       schema.StringAttribute{Optional: true, Description: "Filter by tool name."},
			"decision":        schema.StringAttribute{Optional: true, Description: "Filter by decision type."},
			"reason_code":     schema.StringAttribute{Optional: true, Description: "Filter by reason code."},
			"search":          schema.StringAttribute{Optional: true, Description: "Free-text search query."},
			"from":            schema.StringAttribute{Optional: true, Description: "Start timestamp filter (RFC3339)."},
			"to":              schema.StringAttribute{Optional: true, Description: "End timestamp filter (RFC3339)."},
			"sort_by":         schema.StringAttribute{Optional: true, Description: "Sort field."},
			"sort_dir":        schema.StringAttribute{Optional: true, Description: "Sort direction: asc or desc."},
			"total":           schema.Int64Attribute{Computed: true, Description: "Total matching events."},
			"data_json":       schema.StringAttribute{Computed: true, Description: "Event array as JSON."},
		},
	}
}

func (d *governanceFeedDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governanceFeedDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state governanceFeedModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	if !state.Page.IsNull() && !state.Page.IsUnknown() {
		query["page"] = strconv.FormatInt(state.Page.ValueInt64(), 10)
	}
	if !state.PerPage.IsNull() && !state.PerPage.IsUnknown() {
		query["per_page"] = strconv.FormatInt(state.PerPage.ValueInt64(), 10)
	}
	setQueryString(query, "agent_id", state.AgentID)
	setQueryString(query, "caller_agent_id", state.CallerAgentID)
	setQueryString(query, "tool_name", state.ToolName)
	setQueryString(query, "decision", state.Decision)
	setQueryString(query, "reason_code", state.ReasonCode)
	setQueryString(query, "search", state.Search)
	setQueryString(query, "from", state.From)
	setQueryString(query, "to", state.To)
	setQueryString(query, "sort_by", state.SortBy)
	setQueryString(query, "sort_dir", state.SortDir)

	result, err := d.client.ListGovernanceFeed(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance feed", err.Error())
		return
	}

	state.Total = types.Int64Value(tfhelpers.GetInt64(result, "total"))
	if data, ok := result["data"]; ok {
		state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(data))
	} else {
		state.DataJSON = types.StringValue("[]")
	}

	if v := strings.TrimSpace(tfhelpers.GetString(result, "sort_by")); v != "" {
		state.SortBy = types.StringValue(v)
	}
	if v := strings.TrimSpace(tfhelpers.GetString(result, "sort_dir")); v != "" {
		state.SortDir = types.StringValue(v)
	}

	if v := tfhelpers.GetInt64(result, "page"); v > 0 {
		state.Page = types.Int64Value(v)
	}
	if v := tfhelpers.GetInt64(result, "per_page"); v > 0 {
		state.PerPage = types.Int64Value(v)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func setQueryString(query map[string]string, key string, value types.String) {
	if value.IsNull() || value.IsUnknown() {
		return
	}
	if trimmed := strings.TrimSpace(value.ValueString()); trimmed != "" {
		query[key] = trimmed
	}
}
