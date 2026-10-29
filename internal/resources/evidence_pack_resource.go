package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

// A signed evidence pack is evidence, not configuration: creating this resource
// queues one build, and destroying it only forgets it. Packs stay in Thoth.
// Download and verify them with `thothctl evidence pack download` and
// `thothctl evidence verify --pack`.

var _ resource.Resource = &evidencePackResource{}
var _ resource.ResourceWithImportState = &evidencePackResource{}

// evidencePackPollInterval is how often Create checks a pack it waits for.
var evidencePackPollInterval = 10 * time.Second

type evidencePackResource struct {
	client *client.Client
}

type evidencePackModel struct {
	ID                 types.String `tfsdk:"id"`
	PeriodStart        types.String `tfsdk:"period_start"`
	PeriodEnd          types.String `tfsdk:"period_end"`
	Trigger            types.String `tfsdk:"trigger"`
	WaitForReady       types.Bool   `tfsdk:"wait_for_ready"`
	WaitTimeoutMinutes types.Int64  `tfsdk:"wait_timeout_minutes"`
	Status             types.String `tfsdk:"status"`
	CreatedAt          types.String `tfsdk:"created_at"`
	CompletedAt        types.String `tfsdk:"completed_at"`
	PartCount          types.Int64  `tfsdk:"part_count"`
	TotalsJSON         types.String `tfsdk:"totals_json"`
	Error              types.String `tfsdk:"error"`
}

func NewEvidencePackResource() resource.Resource {
	return &evidencePackResource{}
}

func (r *evidencePackResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_evidence_pack"
}

func (r *evidencePackResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	resp.Schema = schema.Schema{
		Description: "Builds a signed evidence pack for a period. Destroying it removes it from state only; the pack stays in Thoth. Download and verify packs with thothctl.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "Pack ID.", PlanModifiers: keep},
			"period_start": schema.StringAttribute{
				Optional: true, Computed: true,
				Description:   "RFC 3339 start of the period, with period_end. Default: the previous calendar month.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplaceIfConfigured(), stringplanmodifier.UseStateForUnknown()},
			},
			"period_end": schema.StringAttribute{
				Optional: true, Computed: true,
				Description:   "RFC 3339 end of the period, exclusive: at most 31 days after the start, and already passed.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplaceIfConfigured(), stringplanmodifier.UseStateForUnknown()},
			},
			"trigger": schema.StringAttribute{Optional: true, Description: "Change this value to build another pack.", PlanModifiers: replace},
			"wait_for_ready": schema.BoolAttribute{
				Optional: true, Description: "Wait until the pack is ready or failed (default true). A failed build is an error.",
			},
			"wait_timeout_minutes": schema.Int64Attribute{
				Optional: true, Description: "How long to wait (1-120, default 30).",
				Validators: []validator.Int64{int64validator.Between(1, 120)},
			},
			"status":       schema.StringAttribute{Computed: true, Description: "queued, building, ready or failed."},
			"created_at":   schema.StringAttribute{Computed: true, Description: "When the pack was queued.", PlanModifiers: keep},
			"completed_at": schema.StringAttribute{Computed: true, Description: "When the build finished."},
			"part_count":   schema.Int64Attribute{Computed: true, Description: "Number of signed parts in a ready pack."},
			"totals_json":  schema.StringAttribute{Computed: true, Description: "What the pack holds (attestations, chain events, parts) as JSON."},
			"error":        schema.StringAttribute{Computed: true, Description: "Why a build failed."},
		},
	}
}

func (r *evidencePackResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
}

func (r *evidencePackResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan evidencePackModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if (stringOr(plan.PeriodStart) == "") != (stringOr(plan.PeriodEnd) == "") {
		resp.Diagnostics.AddAttributeError(path.Root("period_end"), "Incomplete period", "Set both period_start and period_end, or neither for the previous calendar month.")
		return
	}
	state, err := r.queue(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error queueing evidence pack", err.Error())
		return
	}
	// Save the pack before waiting, so an interrupted wait does not lose it.
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() || !boolOr(plan.WaitForReady, true) {
		return
	}
	state, err = r.wait(ctx, state, time.Duration(int64Or(plan.WaitTimeoutMinutes, 30))*time.Minute)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if err != nil {
		resp.Diagnostics.AddError("Evidence pack not ready", err.Error())
	}
}

func (r *evidencePackResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state evidencePackModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, found, err := r.refresh(ctx, state)
	if err != nil {
		resp.Diagnostics.AddError("Error reading evidence pack", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

// Update only changes how Create waits; the pack itself is never rebuilt in place.
func (r *evidencePackResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state evidencePackModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.WaitForReady = plan.WaitForReady
	state.WaitTimeoutMinutes = plan.WaitTimeoutMinutes
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *evidencePackResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// Packs are evidence and are kept; destroying only removes the resource from state.
}

func (r *evidencePackResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use the pack ID, as `thothctl evidence pack list` shows it.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

// queue asks GovAPI for a pack. When the workspace already has one queued or
// building for the same period, that pack is adopted; for another period it is
// an error, since a workspace builds one pack at a time.
func (r *evidencePackResource) queue(ctx context.Context, plan evidencePackModel) (evidencePackModel, error) {
	pack, err := r.client.CreateEvidencePack(ctx, stringOr(plan.PeriodStart), stringOr(plan.PeriodEnd))
	var apiErr *client.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict {
		var conflict struct {
			Pack map[string]any `json:"pack"`
		}
		if json.Unmarshal([]byte(apiErr.Body), &conflict) != nil || conflict.Pack == nil {
			return plan, err
		}
		if stringOr(plan.PeriodStart) != "" && !(sameInstant(stringOr(plan.PeriodStart), tfhelpers.GetString(conflict.Pack, "period_start")) &&
			sameInstant(stringOr(plan.PeriodEnd), tfhelpers.GetString(conflict.Pack, "period_end"))) {
			return plan, fmt.Errorf("this workspace is already building pack %s for %s to %s; apply again once it finishes",
				tfhelpers.GetString(conflict.Pack, "pack_id"), tfhelpers.GetString(conflict.Pack, "period_start"), tfhelpers.GetString(conflict.Pack, "period_end"))
		}
		pack, err = conflict.Pack, nil
	}
	if err != nil {
		return plan, err
	}
	return applyEvidencePack(plan, pack), nil
}

// wait polls until the pack is ready or failed, or the timeout passes.
func (r *evidencePackResource) wait(ctx context.Context, state evidencePackModel, timeout time.Duration) (evidencePackModel, error) {
	deadline := time.Now().Add(timeout)
	for {
		switch state.Status.ValueString() {
		case "ready":
			return state, nil
		case "failed":
			return state, fmt.Errorf("pack %s failed: %s", state.ID.ValueString(), state.Error.ValueString())
		}
		if time.Now().After(deadline) {
			return state, fmt.Errorf("pack %s is still %s after %s; it keeps building, and the next refresh records the result", state.ID.ValueString(), state.Status.ValueString(), timeout)
		}
		select {
		case <-ctx.Done():
			return state, ctx.Err()
		case <-time.After(evidencePackPollInterval):
		}
		next, found, err := r.refresh(ctx, state)
		if err != nil {
			return state, err
		}
		if !found {
			return state, fmt.Errorf("pack %s is no longer listed", state.ID.ValueString())
		}
		state = next
	}
}

// refresh finds the pack in the workspace's list (there is no single-pack route).
func (r *evidencePackResource) refresh(ctx context.Context, state evidencePackModel) (evidencePackModel, bool, error) {
	result, err := r.client.ListEvidencePacks(ctx)
	if err != nil {
		return state, false, err
	}
	packs, _ := result["packs"].([]any)
	for _, raw := range packs {
		pack, ok := raw.(map[string]any)
		if ok && tfhelpers.GetString(pack, "pack_id") == state.ID.ValueString() {
			return applyEvidencePack(state, pack), true, nil
		}
	}
	return state, false, nil
}

// applyEvidencePack copies a pack into the model. A configured period keeps
// the value as written, since GovAPI returns it normalised to UTC.
func applyEvidencePack(model evidencePackModel, pack map[string]any) evidencePackModel {
	model.ID = types.StringValue(tfhelpers.GetString(pack, "pack_id"))
	if model.PeriodStart.IsNull() || model.PeriodStart.IsUnknown() {
		model.PeriodStart = types.StringValue(tfhelpers.GetString(pack, "period_start"))
	}
	if model.PeriodEnd.IsNull() || model.PeriodEnd.IsUnknown() {
		model.PeriodEnd = types.StringValue(tfhelpers.GetString(pack, "period_end"))
	}
	model.Status = types.StringValue(tfhelpers.GetString(pack, "status"))
	model.CreatedAt = nullableString(pack, "created_at")
	model.CompletedAt = nullableString(pack, "completed_at")
	model.Error = nullableString(pack, "error")
	parts, _ := pack["parts"].([]any)
	model.PartCount = types.Int64Value(int64(len(parts)))
	if totals, ok := pack["totals"]; ok && totals != nil {
		model.TotalsJSON = types.StringValue(tfhelpers.ToJSONString(totals))
	} else {
		model.TotalsJSON = types.StringNull()
	}
	return model
}

func sameInstant(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339, a)
	tb, errB := time.Parse(time.RFC3339, b)
	return errA == nil && errB == nil && ta.Equal(tb)
}

func stringOr(v types.String) string {
	if v.IsNull() || v.IsUnknown() {
		return ""
	}
	return strings.TrimSpace(v.ValueString())
}

func boolOr(v types.Bool, fallback bool) bool {
	if v.IsNull() || v.IsUnknown() {
		return fallback
	}
	return v.ValueBool()
}

func int64Or(v types.Int64, fallback int64) int64 {
	if v.IsNull() || v.IsUnknown() {
		return fallback
	}
	return v.ValueInt64()
}
