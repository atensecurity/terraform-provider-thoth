package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &billingArtifactDataSource{}

type billingArtifactDataSource struct {
	client *client.Client
}

type billingArtifactModel struct {
	Year         types.Int64  `tfsdk:"year"`
	Month        types.Int64  `tfsdk:"month"`
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewBillingArtifactDataSource() datasource.DataSource {
	return &billingArtifactDataSource{}
}

func (d *billingArtifactDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_billing_artifact"
}

func (d *billingArtifactDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads one monthly billing artifact row (PDF/CSV links) by year and month.",
		Attributes: map[string]schema.Attribute{
			"year": schema.Int64Attribute{
				Required:    true,
				Description: "Artifact year (for example: 2026).",
				Validators: []validator.Int64{
					int64validator.Between(2020, 9999),
				},
			},
			"month": schema.Int64Attribute{
				Required:    true,
				Description: "Artifact month (1-12).",
				Validators: []validator.Int64{
					int64validator.Between(1, 12),
				},
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Monthly billing artifact payload as JSON.",
			},
		},
	}
}

func (d *billingArtifactDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *billingArtifactDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state billingArtifactModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := d.client.GetBillingArtifact(ctx, state.Year.ValueInt64(), state.Month.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Error reading billing artifact", err.Error())
		return
	}

	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
