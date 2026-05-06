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

var _ datasource.DataSource = &evidenceVerifyDataSource{}

type evidenceVerifyDataSource struct {
	client *client.Client
}

type evidenceVerifyModel struct {
	Limit          types.Int64  `tfsdk:"limit"`
	Verified       types.Bool   `tfsdk:"verified"`
	RecordsChecked types.Int64  `tfsdk:"records_checked"`
	ChainHead      types.Int64  `tfsdk:"chain_head"`
	BreachDetail   types.String `tfsdk:"breach_detail"`
	ResponseJSON   types.String `tfsdk:"response_json"`
}

func NewEvidenceVerifyDataSource() datasource.DataSource {
	return &evidenceVerifyDataSource{}
}

func (d *evidenceVerifyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_evidence_verify"
}

func (d *evidenceVerifyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Verifies governance evidence WORM chain integrity for the tenant.",
		Attributes: map[string]schema.Attribute{
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of chain records to verify.",
			},
			"verified": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether chain verification succeeded.",
			},
			"records_checked": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of records evaluated by verification.",
			},
			"chain_head": schema.Int64Attribute{
				Computed:    true,
				Description: "Highest verified chain index.",
			},
			"breach_detail": schema.StringAttribute{
				Computed:    true,
				Description: "Verification failure detail when verified is false.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full verification response payload as JSON.",
			},
		},
	}
}

func (d *evidenceVerifyDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *evidenceVerifyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state evidenceVerifyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	if !state.Limit.IsNull() && !state.Limit.IsUnknown() && state.Limit.ValueInt64() > 0 {
		query["limit"] = strconv.FormatInt(state.Limit.ValueInt64(), 10)
	}

	result, err := d.client.VerifyEvidenceChain(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error verifying evidence chain", err.Error())
		return
	}

	state.Verified = types.BoolValue(tfhelpers.GetBool(result, "verified"))
	state.RecordsChecked = types.Int64Value(tfhelpers.GetInt64(result, "records_checked"))
	state.ChainHead = types.Int64Value(tfhelpers.GetInt64(result, "chain_head"))
	state.BreachDetail = nullableString(result, "breach_detail")
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
