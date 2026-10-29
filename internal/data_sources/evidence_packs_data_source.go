package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &evidencePacksDataSource{}

type evidencePacksDataSource struct {
	client *client.Client
}

type evidencePacksModel struct {
	Status   types.String `tfsdk:"status"`
	Total    types.Int64  `tfsdk:"total"`
	DataJSON types.String `tfsdk:"data_json"`
}

func NewEvidencePacksDataSource() datasource.DataSource {
	return &evidencePacksDataSource{}
}

func (d *evidencePacksDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_evidence_packs"
}

func (d *evidencePacksDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists the workspace's signed evidence packs, newest first. Part locations are left out: download and verify packs with thothctl.",
		Attributes: map[string]schema.Attribute{
			"status": schema.StringAttribute{
				Optional:    true,
				Description: "Only packs with this status (queued, building, ready or failed).",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of packs returned.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Packs as a JSON array: pack_id, period_start, period_end, status, created_at, completed_at, part_count, totals, error.",
			},
		},
	}
}

func (d *evidencePacksDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *evidencePacksDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state evidencePacksModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := d.client.ListEvidencePacks(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading evidence packs", err.Error())
		return
	}
	rows := evidencePackRows(result, state.Status.ValueString())
	state.Total = types.Int64Value(int64(len(rows)))
	state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(rows))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// evidencePackRows keeps each pack's summary and drops its part locations.
func evidencePackRows(result map[string]any, status string) []any {
	packs, _ := result["packs"].([]any)
	rows := make([]any, 0, len(packs))
	for _, raw := range packs {
		pack, ok := raw.(map[string]any)
		if !ok || (status != "" && tfhelpers.GetString(pack, "status") != status) {
			continue
		}
		parts, _ := pack["parts"].([]any)
		row := map[string]any{"part_count": len(parts)}
		for _, key := range []string{"pack_id", "period_start", "period_end", "status", "created_at", "completed_at", "totals", "error"} {
			if v, ok := pack[key]; ok && v != nil {
				row[key] = v
			}
		}
		rows = append(rows, row)
	}
	return rows
}
