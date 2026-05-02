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

var _ datasource.DataSource = &mdmSyncJobDataSource{}

type mdmSyncJobDataSource struct {
	client *client.Client
}

type mdmSyncJobModel struct {
	JobID           types.String `tfsdk:"job_id"`
	Provider        types.String `tfsdk:"provider"`
	Status          types.String `tfsdk:"status"`
	SyncedEndpoints types.Int64  `tfsdk:"synced_endpoints"`
	UnassignedCount types.Int64  `tfsdk:"unassigned_count"`
	Error           types.String `tfsdk:"error"`
	StartedAt       types.String `tfsdk:"started_at"`
	CompletedAt     types.String `tfsdk:"completed_at"`
	CreatedAt       types.String `tfsdk:"created_at"`
	UpdatedAt       types.String `tfsdk:"updated_at"`
	JobJSON         types.String `tfsdk:"job_json"`
}

func NewMDMSyncJobDataSource() datasource.DataSource {
	return &mdmSyncJobDataSource{}
}

func (d *mdmSyncJobDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mdm_sync_job"
}

func (d *mdmSyncJobDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads a specific MDM sync job by job_id.",
		Attributes: map[string]schema.Attribute{
			"job_id":           schema.StringAttribute{Required: true, Description: "Sync job identifier."},
			"provider":         schema.StringAttribute{Computed: true, Description: "Provider slug."},
			"status":           schema.StringAttribute{Computed: true, Description: "Job status."},
			"synced_endpoints": schema.Int64Attribute{Computed: true, Description: "Synced endpoint count."},
			"unassigned_count": schema.Int64Attribute{Computed: true, Description: "Unassigned device count."},
			"error":            schema.StringAttribute{Computed: true, Description: "Error message for failed jobs."},
			"started_at":       schema.StringAttribute{Computed: true, Description: "Job start timestamp."},
			"completed_at":     schema.StringAttribute{Computed: true, Description: "Job completion timestamp."},
			"created_at":       schema.StringAttribute{Computed: true, Description: "Job creation timestamp."},
			"updated_at":       schema.StringAttribute{Computed: true, Description: "Job update timestamp."},
			"job_json":         schema.StringAttribute{Computed: true, Description: "Raw job payload as JSON."},
		},
	}
}

func (d *mdmSyncJobDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *mdmSyncJobDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state mdmSyncJobModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	jobID := strings.TrimSpace(state.JobID.ValueString())
	if jobID == "" {
		resp.Diagnostics.AddAttributeError(path.Root("job_id"), "Missing job_id", "job_id must be set.")
		return
	}

	row, err := d.client.GetMDMSyncJob(ctx, jobID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading MDM sync job", err.Error())
		return
	}

	state.Provider = nullableString(row, "provider")
	state.Status = nullableString(row, "status")
	state.SyncedEndpoints = types.Int64Value(tfhelpers.GetInt64(row, "synced_endpoints"))
	state.UnassignedCount = types.Int64Value(tfhelpers.GetInt64(row, "unassigned_count"))
	state.Error = nullableString(row, "error")
	state.StartedAt = nullableString(row, "started_at")
	state.CompletedAt = nullableString(row, "completed_at")
	state.CreatedAt = nullableString(row, "created_at")
	state.UpdatedAt = nullableString(row, "updated_at")
	state.JobJSON = types.StringValue(tfhelpers.ToJSONString(row))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
