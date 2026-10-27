package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &modelArtifactsDataSource{}

type modelArtifactsDataSource struct {
	client *client.Client
}

type modelArtifactsModel struct {
	LifecycleStatus types.String `tfsdk:"lifecycle_status"`
	Total           types.Int64  `tfsdk:"total"`
	DataJSON        types.String `tfsdk:"data_json"`
}

func NewModelArtifactsDataSource() datasource.DataSource {
	return &modelArtifactsDataSource{}
}

func (d *modelArtifactsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_model_artifacts"
}

func (d *modelArtifactsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists model artifacts in Thoth's registry, most recently updated first, with their provenance, screening and activation evidence.",
		Attributes: map[string]schema.Attribute{
			"lifecycle_status": schema.StringAttribute{
				Optional:    true,
				Description: "Filter by lifecycle status: registered, screened, waived, active or rejected.",
				Validators:  []validator.String{stringvalidator.OneOf("registered", "screened", "waived", "active", "rejected")},
			},
			"total": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of matching artifacts.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Matching artifacts as a JSON array.",
			},
		},
	}
}

func (d *modelArtifactsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *modelArtifactsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state modelArtifactsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	query := map[string]string{}
	setQueryString(query, "lifecycle_status", state.LifecycleStatus)
	result, err := d.client.ListModelArtifacts(ctx, query)
	if err != nil {
		resp.Diagnostics.AddError("Error reading model artifacts", err.Error())
		return
	}
	state.Total = types.Int64Value(tfhelpers.GetInt64(result, "total"))
	if data, ok := result["data"]; ok {
		state.DataJSON = types.StringValue(tfhelpers.ToJSONArrayString(data))
	} else {
		state.DataJSON = types.StringValue("[]")
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
