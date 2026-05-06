package data_sources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &evidenceBundleDataSource{}

type evidenceBundleDataSource struct {
	client *client.Client
}

type evidenceBundleModel struct {
	SessionID    types.String `tfsdk:"session_id"`
	BundleHash   types.String `tfsdk:"bundle_hash"`
	ExportedAt   types.String `tfsdk:"exported_at"`
	SummaryJSON  types.String `tfsdk:"summary_json"`
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewEvidenceBundleDataSource() datasource.DataSource {
	return &evidenceBundleDataSource{}
}

func (d *evidenceBundleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_evidence_bundle"
}

func (d *evidenceBundleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads the exported evidence bundle for a specific session.",
		Attributes: map[string]schema.Attribute{
			"session_id": schema.StringAttribute{
				Required:    true,
				Description: "Target session ID.",
			},
			"bundle_hash": schema.StringAttribute{
				Computed:    true,
				Description: "Deterministic bundle hash for integrity checks.",
			},
			"exported_at": schema.StringAttribute{
				Computed:    true,
				Description: "Bundle export timestamp.",
			},
			"summary_json": schema.StringAttribute{
				Computed:    true,
				Description: "Bundle summary object as JSON.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full evidence bundle response payload as JSON.",
			},
		},
	}
}

func (d *evidenceBundleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *evidenceBundleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state evidenceBundleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	sessionID := strings.TrimSpace(state.SessionID.ValueString())
	if sessionID == "" {
		resp.Diagnostics.AddAttributeError(path.Root("session_id"), "Missing session_id", "session_id must be set.")
		return
	}
	state.SessionID = types.StringValue(sessionID)

	result, err := d.client.GetSessionEvidenceBundle(ctx, sessionID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading evidence bundle", err.Error())
		return
	}

	state.BundleHash = nullableString(result, "bundle_hash")
	state.ExportedAt = nullableString(result, "exported_at")
	if summary, ok := result["summary"]; ok {
		state.SummaryJSON = types.StringValue(tfhelpers.ToJSONString(summary))
	} else {
		state.SummaryJSON = types.StringValue("{}")
	}
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
