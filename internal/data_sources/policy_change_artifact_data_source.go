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

var _ datasource.DataSource = &policyChangeArtifactDataSource{}

type policyChangeArtifactDataSource struct {
	client *client.Client
}

type policyChangeArtifactModel struct {
	RequestID         types.String `tfsdk:"request_id"`
	ArtifactID        types.String `tfsdk:"artifact_id"`
	TargetEnvironment types.String `tfsdk:"target_environment"`
	UpdatedAt         types.String `tfsdk:"updated_at"`
	DataJSON          types.String `tfsdk:"data_json"`
}

func NewPolicyChangeArtifactDataSource() datasource.DataSource {
	return &policyChangeArtifactDataSource{}
}

func (d *policyChangeArtifactDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_change_artifact"
}

func (d *policyChangeArtifactDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads a policy change artifact for an exception request.",
		Attributes: map[string]schema.Attribute{
			"request_id": schema.StringAttribute{
				Required:    true,
				Description: "Policy exception request ID.",
			},
			"artifact_id": schema.StringAttribute{
				Computed:    true,
				Description: "Policy change artifact ID.",
			},
			"target_environment": schema.StringAttribute{
				Computed:    true,
				Description: "Target environment for the artifact.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Last artifact update timestamp.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full policy change artifact as JSON.",
			},
		},
	}
}

func (d *policyChangeArtifactDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *policyChangeArtifactDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state policyChangeArtifactModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	requestID := strings.TrimSpace(state.RequestID.ValueString())
	if requestID == "" {
		resp.Diagnostics.AddError("Missing request_id", "request_id must be provided.")
		return
	}

	row, err := d.client.GetPolicyChangeArtifact(ctx, requestID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy change artifact", err.Error())
		return
	}

	state.RequestID = types.StringValue(requestID)
	state.ArtifactID = nullableString(row, "artifact_id")
	state.TargetEnvironment = nullableString(row, "target_environment")
	state.UpdatedAt = nullableString(row, "updated_at")
	state.DataJSON = types.StringValue(tfhelpers.ToJSONString(row))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
