package data_sources

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &evidenceChainDataSource{}

type evidenceChainDataSource struct {
	client *client.Client
}

type evidenceChainModel struct {
	Limit        types.Int64  `tfsdk:"limit"`
	FromSequence types.Int64  `tfsdk:"from_sequence"`
	Total        types.Int64  `tfsdk:"total"`
	DataJSON     types.String `tfsdk:"data_json"`
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewEvidenceChainDataSource() datasource.DataSource {
	return &evidenceChainDataSource{}
}

func (d *evidenceChainDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_evidence_chain"
}

func (d *evidenceChainDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads WORM evidence chain records for the tenant.",
		Attributes: map[string]schema.Attribute{
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of evidence chain records to return (1-500).",
			},
			"from_sequence": schema.Int64Attribute{
				Optional:    true,
				Description: "Optional chain sequence cursor. Returns rows with chain_index greater than this value.",
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Total evidence chain records returned.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Evidence chain rows as JSON array.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full evidence chain response payload as JSON.",
			},
		},
	}
}

func (d *evidenceChainDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *evidenceChainDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state evidenceChainModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	if !state.Limit.IsNull() && !state.Limit.IsUnknown() && state.Limit.ValueInt64() > 0 {
		query["limit"] = strconv.FormatInt(state.Limit.ValueInt64(), 10)
	}
	if !state.FromSequence.IsNull() && !state.FromSequence.IsUnknown() && state.FromSequence.ValueInt64() >= 0 {
		query["from_sequence"] = strconv.FormatInt(state.FromSequence.ValueInt64(), 10)
	}

	result, err := d.client.GetEvidenceChain(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading evidence chain", err.Error())
		return
	}

	state.Total = types.Int64Value(tfhelpers.GetInt64(result, "total"))
	if raw, ok := result["data"]; ok {
		state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(raw))
	} else if raw, ok := result["chain"]; ok {
		state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(raw))
	} else {
		state.DataJSON = types.StringValue("[]")
	}
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
