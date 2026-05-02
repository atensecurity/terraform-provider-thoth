package resources

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &policySyncResource{}
var _ resource.ResourceWithImportState = &policySyncResource{}

type policySyncResource struct {
	client   *client.Client
	tenantID string
}

type policySyncModel struct {
	ID                types.String `tfsdk:"id"`
	TenantID          types.String `tfsdk:"tenant_id"`
	Trigger           types.String `tfsdk:"trigger"`
	WaitForCompletion types.Bool   `tfsdk:"wait_for_completion"`
	PollIntervalSecs  types.Int64  `tfsdk:"poll_interval_seconds"`
	TimeoutSecs       types.Int64  `tfsdk:"timeout_seconds"`
	Configured        types.Bool   `tfsdk:"configured"`
	Status            types.String `tfsdk:"status"`
	SyncedAt          types.String `tfsdk:"synced_at"`
	Changed           types.Bool   `tfsdk:"changed"`
	AppliedCount      types.Int64  `tfsdk:"applied_count"`
	AppliedAgentsJSON types.String `tfsdk:"applied_agents_json"`
	SkippedCount      types.Int64  `tfsdk:"skipped_count"`
	ErrorCount        types.Int64  `tfsdk:"error_count"`
	ErrorsJSON        types.String `tfsdk:"errors_json"`
	IntervalSeconds   types.Int64  `tfsdk:"interval_seconds"`
}

func NewPolicySyncResource() resource.Resource {
	return &policySyncResource{}
}

func (r *policySyncResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_sync"
}

func (r *policySyncResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Triggers Thoth policy sync and tracks sync status.",
		Attributes: map[string]schema.Attribute{
			"id":                  schema.StringAttribute{Computed: true, Description: "Synthetic sync execution ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":           schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"trigger":             schema.StringAttribute{Optional: true, Description: "Change this value to force a sync run.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"wait_for_completion": schema.BoolAttribute{Optional: true, Description: "Poll status until terminal state."},
			"poll_interval_seconds": schema.Int64Attribute{
				Optional:    true,
				Description: "Polling interval when wait_for_completion=true.",
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
				},
			},
			"timeout_seconds": schema.Int64Attribute{
				Optional:    true,
				Description: "Polling timeout when wait_for_completion=true.",
				Validators: []validator.Int64{
					int64validator.AtLeast(5),
				},
			},
			"configured":          schema.BoolAttribute{Computed: true, Description: "Whether policy sync is configured."},
			"status":              schema.StringAttribute{Computed: true, Description: "Current policy sync status."},
			"synced_at":           schema.StringAttribute{Computed: true, Description: "Last sync timestamp."},
			"changed":             schema.BoolAttribute{Computed: true, Description: "Whether sync applied changes."},
			"applied_count":       schema.Int64Attribute{Computed: true, Description: "Policies applied during sync."},
			"applied_agents_json": schema.StringAttribute{Computed: true, Description: "Applied agent IDs as JSON array."},
			"skipped_count":       schema.Int64Attribute{Computed: true, Description: "Skipped policy entries count."},
			"error_count":         schema.Int64Attribute{Computed: true, Description: "Sync error count."},
			"errors_json":         schema.StringAttribute{Computed: true, Description: "Sync errors as JSON array."},
			"interval_seconds":    schema.Int64Attribute{Computed: true, Description: "Configured enforcer sync interval seconds."},
		},
	}
}

func (r *policySyncResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *policySyncResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policySyncModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.triggerAndRead(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error triggering policy sync", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policySyncResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policySyncModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	row, err := r.client.GetPolicySyncStatus(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy sync status", err.Error())
		return
	}
	next := flattenPolicySync(row, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policySyncResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policySyncModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.triggerAndRead(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error triggering policy sync", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policySyncResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No remote delete operation.
}

func (r *policySyncResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importID := strings.TrimSpace(req.ID)
	if importID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use any non-empty identifier, for example policy-sync.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), importID)...)
}

func (r *policySyncResource) triggerAndRead(ctx context.Context, plan policySyncModel) (policySyncModel, error) {
	row, err := r.client.TriggerPolicySync(ctx)
	if err != nil {
		return policySyncModel{}, err
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
		timeout := int64(180)
		if !plan.TimeoutSecs.IsNull() && !plan.TimeoutSecs.IsUnknown() && plan.TimeoutSecs.ValueInt64() > 0 {
			timeout = plan.TimeoutSecs.ValueInt64()
		}
		finalRow, pollErr := r.pollSyncStatus(ctx, time.Duration(pollEvery)*time.Second, time.Duration(timeout)*time.Second)
		if pollErr == nil {
			row = finalRow
		}
	}

	next := flattenPolicySync(row, plan, r.tenantID)
	if next.ID.IsNull() || next.ID.IsUnknown() || strings.TrimSpace(next.ID.ValueString()) == "" {
		next.ID = types.StringValue(fmt.Sprintf("%s/%d", r.tenantID, time.Now().UTC().Unix()))
	}
	return next, nil
}

func (r *policySyncResource) pollSyncStatus(ctx context.Context, interval time.Duration, timeout time.Duration) (map[string]any, error) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		row, err := r.client.GetPolicySyncStatus(deadlineCtx)
		if err != nil {
			return nil, err
		}
		status := strings.ToLower(tfhelpers.GetString(row, "status"))
		switch status {
		case "success", "error", "disabled", "no_change", "partial", "idle":
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

func flattenPolicySync(row map[string]any, current policySyncModel, tenantID string) policySyncModel {
	next := current
	if next.ID.IsNull() || next.ID.IsUnknown() || strings.TrimSpace(next.ID.ValueString()) == "" {
		next.ID = types.StringValue(fmt.Sprintf("%s/%s", tenantID, time.Now().UTC().Format(time.RFC3339)))
	}
	next.TenantID = types.StringValue(tenantID)
	next.Configured = types.BoolValue(tfhelpers.GetBool(row, "configured"))
	next.Status = nullableString(row, "status")
	next.SyncedAt = nullableString(row, "synced_at")
	next.Changed = types.BoolValue(tfhelpers.GetBool(row, "changed"))
	next.AppliedCount = types.Int64Value(tfhelpers.GetInt64(row, "applied_count"))
	next.AppliedAgentsJSON = types.StringValue(tfhelpers.ToJSONArrayString(row["applied_agents"]))
	next.SkippedCount = types.Int64Value(tfhelpers.GetInt64(row, "skipped_count"))
	next.ErrorCount = types.Int64Value(tfhelpers.GetInt64(row, "error_count"))
	next.ErrorsJSON = types.StringValue(tfhelpers.ToJSONArrayString(row["errors"]))
	next.IntervalSeconds = types.Int64Value(tfhelpers.GetInt64(row, "interval_seconds"))
	return next
}
