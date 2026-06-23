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

var _ datasource.DataSource = &policyExceptionDataSource{}

type policyExceptionDataSource struct {
	client *client.Client
}

type policyExceptionModel struct {
	RequestID   types.String `tfsdk:"request_id"`
	Status      types.String `tfsdk:"status"`
	RequestedBy types.String `tfsdk:"requested_by"`
	ReviewedBy  types.String `tfsdk:"reviewed_by"`
	UpdatedAt   types.String `tfsdk:"updated_at"`
	DataJSON    types.String `tfsdk:"data_json"`
}

func NewPolicyExceptionDataSource() datasource.DataSource {
	return &policyExceptionDataSource{}
}

func (d *policyExceptionDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_exception"
}

func (d *policyExceptionDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads a single policy exception request by request ID.",
		Attributes: map[string]schema.Attribute{
			"request_id": schema.StringAttribute{
				Required:    true,
				Description: "Policy exception request ID.",
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Current exception request status.",
			},
			"requested_by": schema.StringAttribute{
				Computed:    true,
				Description: "User who requested the exception.",
			},
			"reviewed_by": schema.StringAttribute{
				Computed:    true,
				Description: "Reviewer identity when available.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Last update timestamp.",
			},
			"data_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full policy exception object as JSON.",
			},
		},
	}
}

func (d *policyExceptionDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *policyExceptionDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state policyExceptionModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	requestID := strings.TrimSpace(state.RequestID.ValueString())
	if requestID == "" {
		resp.Diagnostics.AddError("Missing request_id", "request_id must be provided.")
		return
	}

	row, err := d.client.GetPolicyException(ctx, requestID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy exception", err.Error())
		return
	}

	state.RequestID = types.StringValue(requestID)
	state.Status = nullableString(row, "status")
	state.RequestedBy = nullableString(row, "requested_by")
	state.ReviewedBy = nullableString(row, "reviewed_by")
	state.UpdatedAt = nullableString(row, "updated_at")
	state.DataJSON = types.StringValue(tfhelpers.ToJSONString(row))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
