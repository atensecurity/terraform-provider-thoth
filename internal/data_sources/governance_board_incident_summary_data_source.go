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

var _ datasource.DataSource = &governanceBoardIncidentSummaryDataSource{}

type governanceBoardIncidentSummaryDataSource struct {
	client *client.Client
}

type governanceBoardIncidentSummaryModel struct {
	ViolationID  types.String `tfsdk:"violation_id"`
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewGovernanceBoardIncidentSummaryDataSource() datasource.DataSource {
	return &governanceBoardIncidentSummaryDataSource{}
}

func (d *governanceBoardIncidentSummaryDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_governance_board_incident_summary"
}

func (d *governanceBoardIncidentSummaryDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Description: "Reads a board-ready incident summary for a specific violation.",
		Attributes: map[string]schema.Attribute{
			"violation_id": schema.StringAttribute{
				Required:    true,
				Description: "Violation ID to retrieve.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Board incident summary payload as JSON.",
			},
		},
	}
}

func (d *governanceBoardIncidentSummaryDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *governanceBoardIncidentSummaryDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var state governanceBoardIncidentSummaryModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	violationID := strings.TrimSpace(state.ViolationID.ValueString())
	if violationID == "" {
		resp.Diagnostics.AddError("Missing violation_id", "violation_id must be non-empty.")
		return
	}

	result, err := d.client.GetBoardIncidentSummary(ctx, violationID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance board incident summary", err.Error())
		return
	}

	state.ViolationID = types.StringValue(violationID)
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
