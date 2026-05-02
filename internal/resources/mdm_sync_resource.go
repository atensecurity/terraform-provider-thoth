package resources

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &mdmSyncResource{}
var _ resource.ResourceWithImportState = &mdmSyncResource{}

type mdmSyncResource struct {
	client   *client.Client
	tenantID string
}

type mdmSyncModel struct {
	ID                types.String `tfsdk:"id"`
	TenantID          types.String `tfsdk:"tenant_id"`
	ProviderName      types.String `tfsdk:"provider_name"`
	Trigger           types.String `tfsdk:"trigger"`
	WaitForCompletion types.Bool   `tfsdk:"wait_for_completion"`
	PollIntervalSecs  types.Int64  `tfsdk:"poll_interval_seconds"`
	TimeoutSecs       types.Int64  `tfsdk:"timeout_seconds"`
	Status            types.String `tfsdk:"status"`
	SyncedEndpoints   types.Int64  `tfsdk:"synced_endpoints"`
	UnassignedCount   types.Int64  `tfsdk:"unassigned_count"`
	Error             types.String `tfsdk:"error"`
	StartedAt         types.String `tfsdk:"started_at"`
	CompletedAt       types.String `tfsdk:"completed_at"`
	CreatedAt         types.String `tfsdk:"created_at"`
	UpdatedAt         types.String `tfsdk:"updated_at"`
}

func NewMDMSyncResource() resource.Resource {
	return &mdmSyncResource{}
}

func (r *mdmSyncResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mdm_sync"
}

func (r *mdmSyncResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Triggers and tracks an MDM sync job.",
		Attributes: map[string]schema.Attribute{
			"id":                    schema.StringAttribute{Computed: true, Description: "Sync job ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":             schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"provider_name":         schema.StringAttribute{Required: true, Description: "MDM provider slug.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"trigger":               schema.StringAttribute{Optional: true, Description: "Arbitrary replacement trigger value.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"wait_for_completion":   schema.BoolAttribute{Optional: true, Description: "Wait for sync job completion before returning state."},
			"poll_interval_seconds": schema.Int64Attribute{Optional: true, Description: "Polling interval when wait_for_completion=true."},
			"timeout_seconds":       schema.Int64Attribute{Optional: true, Description: "Polling timeout when wait_for_completion=true."},
			"status":                schema.StringAttribute{Computed: true, Description: "Job status: queued, running, succeeded, failed."},
			"synced_endpoints":      schema.Int64Attribute{Computed: true, Description: "Number of endpoints synchronized by the job."},
			"unassigned_count":      schema.Int64Attribute{Computed: true, Description: "Count of devices that could not be mapped."},
			"error":                 schema.StringAttribute{Computed: true, Description: "Job error string when status=failed."},
			"started_at":            schema.StringAttribute{Computed: true, Description: "Job start timestamp."},
			"completed_at":          schema.StringAttribute{Computed: true, Description: "Job completion timestamp."},
			"created_at":            schema.StringAttribute{Computed: true, Description: "Job creation timestamp."},
			"updated_at":            schema.StringAttribute{Computed: true, Description: "Job update timestamp."},
		},
	}
}

func (r *mdmSyncResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *mdmSyncResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan mdmSyncModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, ok := r.runSync(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *mdmSyncResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state mdmSyncModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	row, err := r.client.GetMDMSyncJob(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading MDM sync job", err.Error())
		return
	}

	next := flattenMDMSync(row, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *mdmSyncResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan mdmSyncModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, ok := r.runSync(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *mdmSyncResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// Sync jobs are historical records and are not deleted via API.
}

func (r *mdmSyncResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	jobID := strings.TrimSpace(req.ID)
	if jobID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use sync job ID as import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), jobID)...)
}

func (r *mdmSyncResource) runSync(ctx context.Context, plan mdmSyncModel, diags *diag.Diagnostics) (mdmSyncModel, bool) {
	provider := strings.TrimSpace(plan.ProviderName.ValueString())
	if provider == "" {
		diags.AddAttributeError(path.Root("provider_name"), "Missing provider", "provider_name must be set.")
		return mdmSyncModel{}, false
	}

	row, err := r.client.StartMDMSync(ctx, provider)
	if err != nil {
		diags.AddError("Error starting MDM sync", err.Error())
		return mdmSyncModel{}, false
	}

	wait := true
	if !plan.WaitForCompletion.IsNull() && !plan.WaitForCompletion.IsUnknown() {
		wait = plan.WaitForCompletion.ValueBool()
	}
	if wait {
		pollEvery := int64(5)
		if !plan.PollIntervalSecs.IsNull() && !plan.PollIntervalSecs.IsUnknown() && plan.PollIntervalSecs.ValueInt64() > 0 {
			pollEvery = plan.PollIntervalSecs.ValueInt64()
		}
		timeout := int64(300)
		if !plan.TimeoutSecs.IsNull() && !plan.TimeoutSecs.IsUnknown() && plan.TimeoutSecs.ValueInt64() > 0 {
			timeout = plan.TimeoutSecs.ValueInt64()
		}

		finalRow, pollErr := r.pollSyncJob(ctx, tfhelpers.GetString(row, "job_id"), time.Duration(pollEvery)*time.Second, time.Duration(timeout)*time.Second)
		if pollErr != nil {
			diags.AddWarning("Polling MDM sync job failed", pollErr.Error())
		} else {
			row = finalRow
		}
	}

	return flattenMDMSync(row, plan, r.tenantID), true
}

func (r *mdmSyncResource) pollSyncJob(ctx context.Context, jobID string, interval time.Duration, timeout time.Duration) (map[string]any, error) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		row, err := r.client.GetMDMSyncJob(deadlineCtx, jobID)
		if err != nil {
			return nil, err
		}
		status := strings.ToLower(tfhelpers.GetString(row, "status"))
		switch status {
		case "succeeded", "failed":
			return row, nil
		}

		timer := time.NewTimer(interval)
		select {
		case <-deadlineCtx.Done():
			timer.Stop()
			return row, deadlineCtx.Err()
		case <-timer.C:
		}
	}
}

func flattenMDMSync(row map[string]any, current mdmSyncModel, tenantID string) mdmSyncModel {
	next := current
	next.ID = types.StringValue(tfhelpers.GetString(row, "job_id"))
	next.TenantID = types.StringValue(tenantID)
	next.ProviderName = nullableString(row, "provider")
	next.Status = nullableString(row, "status")
	next.SyncedEndpoints = types.Int64Value(tfhelpers.GetInt64(row, "synced_endpoints"))
	next.UnassignedCount = types.Int64Value(tfhelpers.GetInt64(row, "unassigned_count"))
	next.Error = nullableString(row, "error")
	next.StartedAt = nullableString(row, "started_at")
	next.CompletedAt = nullableString(row, "completed_at")
	next.CreatedAt = nullableString(row, "created_at")
	next.UpdatedAt = nullableString(row, "updated_at")
	return next
}
