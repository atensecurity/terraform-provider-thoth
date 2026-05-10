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

var _ datasource.DataSource = &billingArtifactsDataSource{}

type billingArtifactsDataSource struct {
	client *client.Client
}

type billingArtifactsModel struct {
	Limit         types.Int64  `tfsdk:"limit"`
	TotalCount    types.Int64  `tfsdk:"total_count"`
	ArtifactsJSON types.String `tfsdk:"artifacts_json"`
	ResponseJSON  types.String `tfsdk:"response_json"`
}

func NewBillingArtifactsDataSource() datasource.DataSource {
	return &billingArtifactsDataSource{}
}

func (d *billingArtifactsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_billing_artifacts"
}

func (d *billingArtifactsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads monthly billing artifacts (PDF/CSV links) for recent billing periods.",
		Attributes: map[string]schema.Attribute{
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of monthly artifact rows to return.",
			},
			"total_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Total artifact rows returned.",
			},
			"artifacts_json": schema.StringAttribute{
				Computed:    true,
				Description: "Monthly artifact rows as JSON array.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full billing artifacts response payload as JSON.",
			},
		},
	}
}

func (d *billingArtifactsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *billingArtifactsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state billingArtifactsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	query := map[string]string{}
	if !state.Limit.IsNull() && !state.Limit.IsUnknown() && state.Limit.ValueInt64() > 0 {
		query["limit"] = strconv.FormatInt(state.Limit.ValueInt64(), 10)
	}

	result, err := d.client.ListBillingArtifacts(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading billing artifacts", err.Error())
		return
	}

	state.TotalCount = types.Int64Value(tfhelpers.GetInt64(result, "count"))
	if raw, ok := result["artifacts"]; ok {
		state.ArtifactsJSON = types.StringValue(tfhelpers.ToJSONArrayString(raw))
	} else {
		state.ArtifactsJSON = types.StringValue("[]")
	}
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
