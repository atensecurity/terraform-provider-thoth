package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/float64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/float64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

const siemDecisionStreamDefaultDecisions = "non_allow"

var _ resource.Resource = &siemDecisionStreamResource{}
var _ resource.ResourceWithImportState = &siemDecisionStreamResource{}

type siemDecisionStreamResource struct {
	client   *client.Client
	tenantID string
}

type siemDecisionStreamModel struct {
	ID              types.String  `tfsdk:"id"`
	TenantID        types.String  `tfsdk:"tenant_id"`
	Enabled         types.Bool    `tfsdk:"enabled"`
	Decisions       types.String  `tfsdk:"decisions"`
	AllowSampleRate types.Float64 `tfsdk:"allow_sample_rate"`
}

func NewSIEMDecisionStreamResource() resource.Resource {
	return &siemDecisionStreamResource{}
}

func (r *siemDecisionStreamResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_siem_decision_stream"
}

func (r *siemDecisionStreamResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Sends enforcement decisions to the workspace's SIEM destination as they are recorded. " +
			"Needs a SIEM destination first (`thoth_siem_settings`; add `depends_on`). Prompts are never sent, " +
			"and tool arguments only as `thoth_data_handling` keeps them. Destroying this resource turns the stream off.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Terraform resource identifier (tenant ID).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant_id": schema.StringAttribute{
				Computed:    true,
				Description: "Tenant ID resolved from provider configuration.",
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Whether decisions are sent. Default `true`.",
			},
			"decisions": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(siemDecisionStreamDefaultDecisions),
				Description: "`non_allow` sends holds and blocks (default); `all` sends every decision.",
				Validators:  []validator.String{stringvalidator.OneOf("non_allow", "all")},
			},
			"allow_sample_rate": schema.Float64Attribute{
				Optional: true,
				Computed: true,
				Default:  float64default.StaticFloat64(1),
				Description: "With `decisions = \"all\"`, the share of `ALLOW` decisions sent, from 0 to 1 (default 1). " +
					"Holds and blocks are never sampled.",
				Validators: []validator.Float64{float64validator.Between(0, 1)},
			},
		},
	}
}

func (r *siemDecisionStreamResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *siemDecisionStreamResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan siemDecisionStreamModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.apply(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error setting the SIEM decision stream", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *siemDecisionStreamResource) Read(ctx context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	out, err := r.client.GetSIEMDecisionStream(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading the SIEM decision stream", err.Error())
		return
	}
	next := flattenSIEMDecisionStream(out, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *siemDecisionStreamResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan siemDecisionStreamModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.apply(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error updating the SIEM decision stream", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

// Delete turns the stream off and returns the other choices to their defaults.
func (r *siemDecisionStreamResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if _, err := r.client.UpdateSIEMDecisionStream(ctx, false, siemDecisionStreamDefaultDecisions, 1); err != nil {
		resp.Diagnostics.AddError("Error turning off the SIEM decision stream", err.Error())
	}
}

func (r *siemDecisionStreamResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importID := strings.TrimSpace(req.ID)
	if importID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use tenant ID as import identifier.")
		return
	}
	if r.tenantID != "" && importID != r.tenantID {
		resp.Diagnostics.AddWarning(
			"Tenant mismatch",
			fmt.Sprintf("Imported tenant %q does not match provider tenant %q; provider tenant will be used.", importID, r.tenantID),
		)
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), r.tenantID)...)
}

func (r *siemDecisionStreamResource) apply(ctx context.Context, plan siemDecisionStreamModel) (siemDecisionStreamModel, error) {
	out, err := r.client.UpdateSIEMDecisionStream(ctx, plan.Enabled.ValueBool(), plan.Decisions.ValueString(), plan.AllowSampleRate.ValueFloat64())
	if err != nil {
		return siemDecisionStreamModel{}, err
	}
	return flattenSIEMDecisionStream(out, r.tenantID), nil
}

func flattenSIEMDecisionStream(out map[string]any, tenantID string) siemDecisionStreamModel {
	enabled, _ := out["enabled"].(bool)
	decisions := tfhelpers.GetString(out, "decisions")
	if decisions == "" {
		decisions = siemDecisionStreamDefaultDecisions
	}
	rate := 1.0
	if value, ok := out["allow_sample_rate"].(float64); ok {
		rate = value
	}
	return siemDecisionStreamModel{
		ID:              types.StringValue(tenantID),
		TenantID:        types.StringValue(tenantID),
		Enabled:         types.BoolValue(enabled),
		Decisions:       types.StringValue(decisions),
		AllowSampleRate: types.Float64Value(rate),
	}
}
