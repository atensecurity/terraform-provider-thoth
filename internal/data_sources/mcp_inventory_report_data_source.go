package data_sources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

const defaultMCPInventoryWindowHours int64 = 24 * 7

var _ datasource.DataSource = &mcpInventoryReportDataSource{}

type mcpInventoryReportDataSource struct {
	client *client.Client
}

type mcpInventoryReportDataSourceModel struct {
	WindowHours         types.Int64  `tfsdk:"window_hours"`
	Total               types.Int64  `tfsdk:"total"`
	UnapprovedEndpoints types.Int64  `tfsdk:"unapproved_endpoints"`
	UnapprovedCalls     types.Int64  `tfsdk:"unapproved_calls"`
	DataJSON            types.String `tfsdk:"data_json"`
	ResponseJSON        types.String `tfsdk:"response_json"`
}

func NewMCPInventoryReportDataSource() datasource.DataSource {
	return &mcpInventoryReportDataSource{}
}

func (d *mcpInventoryReportDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mcp_inventory_report"
}

func (d *mcpInventoryReportDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads the MCP endpoint inventory report for a tenant window.",
		Attributes: map[string]schema.Attribute{
			"window_hours": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Report lookback window in hours. Defaults to 168.",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total endpoint rows in the report.",
			},
			"unapproved_endpoints": schema.Int64Attribute{
				Computed:    true,
				Description: "Count of endpoints with one or more unapproved MCP calls.",
			},
			"unapproved_calls": schema.Int64Attribute{
				Computed:    true,
				Description: "Total unapproved MCP calls across all endpoints.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Inventory rows as JSON array.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full report payload as JSON.",
			},
		},
	}
}

func (d *mcpInventoryReportDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *mcpInventoryReportDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state mcpInventoryReportDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	windowHours := defaultMCPInventoryWindowHours
	if !state.WindowHours.IsNull() && !state.WindowHours.IsUnknown() && state.WindowHours.ValueInt64() > 0 {
		windowHours = state.WindowHours.ValueInt64()
	}

	report, err := d.client.GetMCPInventoryReport(ctx, windowHours)
	if err != nil {
		resp.Diagnostics.AddError("Error reading MCP inventory report", err.Error())
		return
	}

	rows, err := mcpInventoryRows(report)
	if err != nil {
		resp.Diagnostics.AddError("Error decoding MCP inventory report", err.Error())
		return
	}

	total := int64(len(rows))
	if computedTotal := int64FromAny(report["total"]); computedTotal > 0 {
		total = computedTotal
	}

	var unapprovedEndpoints int64
	var unapprovedCalls int64
	for _, row := range rows {
		calls := int64FromAny(row["unapproved_calls"])
		if calls > 0 {
			unapprovedEndpoints++
			unapprovedCalls += calls
		}
	}

	state.WindowHours = types.Int64Value(windowHours)
	state.Total = types.Int64Value(total)
	state.UnapprovedEndpoints = types.Int64Value(unapprovedEndpoints)
	state.UnapprovedCalls = types.Int64Value(unapprovedCalls)
	state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(rows))
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(report))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func mcpInventoryRows(payload map[string]any) ([]map[string]any, error) {
	raw, ok := payload["data"]
	if !ok || raw == nil {
		return []map[string]any{}, nil
	}

	rows, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("data is not an array")
	}

	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		typed, ok := row.(map[string]any)
		if ok {
			result = append(result, typed)
			continue
		}
		if bsonRow, ok := row.(map[string]interface{}); ok {
			result = append(result, map[string]any(bsonRow))
			continue
		}
	}
	return result, nil
}

func int64FromAny(input any) int64 {
	switch typed := input.(type) {
	case int64:
		return typed
	case int32:
		return int64(typed)
	case int:
		return int64(typed)
	case float64:
		return int64(typed)
	case float32:
		return int64(typed)
	case json.Number:
		v, _ := typed.Int64()
		return v
	default:
		return 0
	}
}
