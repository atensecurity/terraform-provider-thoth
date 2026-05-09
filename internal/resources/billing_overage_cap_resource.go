package resources

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &billingOverageCapResource{}
var _ resource.ResourceWithImportState = &billingOverageCapResource{}

type billingOverageCapResource struct {
	client   *client.Client
	tenantID string
}

type billingOverageCapModel struct {
	ID                          types.String  `tfsdk:"id"`
	TenantID                    types.String  `tfsdk:"tenant_id"`
	OverageCapUSD               types.Float64 `tfsdk:"overage_cap_usd"`
	ActiveTier                  types.String  `tfsdk:"active_tier"`
	BaseMonthlyPlatformFeeUSD   types.Float64 `tfsdk:"base_monthly_platform_fee_usd"`
	IncludedGovernedIdentities  types.Int64   `tfsdk:"included_governed_identities"`
	IncludedPolicyChecks        types.Int64   `tfsdk:"included_policy_checks"`
	GovernedIdentityUSDPerMonth types.Float64 `tfsdk:"governed_identity_usd_per_month"`
	PolicyChecksUSDPerMillion   types.Float64 `tfsdk:"policy_checks_usd_per_million"`
	UpdatedAt                   types.String  `tfsdk:"updated_at"`
	ResponseJSON                types.String  `tfsdk:"response_json"`
}

func NewBillingOverageCapResource() resource.Resource {
	return &billingOverageCapResource{}
}

func (r *billingOverageCapResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_billing_overage_cap"
}

func (r *billingOverageCapResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages customer-controlled monthly overage cap while Aten-managed base pricing remains immutable.",
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
			"overage_cap_usd": schema.Float64Attribute{
				Required:    true,
				Description: "Monthly variable overage cap in USD.",
			},
			"active_tier": schema.StringAttribute{
				Computed:    true,
				Description: "Effective active pricing tier.",
			},
			"base_monthly_platform_fee_usd": schema.Float64Attribute{
				Computed:    true,
				Description: "Base monthly platform fee in USD for the active tier.",
			},
			"included_governed_identities": schema.Int64Attribute{
				Computed:    true,
				Description: "Included governed identities before overage.",
			},
			"included_policy_checks": schema.Int64Attribute{
				Computed:    true,
				Description: "Included policy checks before overage.",
			},
			"governed_identity_usd_per_month": schema.Float64Attribute{
				Computed:    true,
				Description: "Per-governed-identity overage rate.",
			},
			"policy_checks_usd_per_million": schema.Float64Attribute{
				Computed:    true,
				Description: "Per-million policy checks overage rate.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the overage cap was last applied via provider.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Full billing pricing profile response payload as JSON.",
			},
		},
	}
}

func (r *billingOverageCapResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *billingOverageCapResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan billingOverageCapModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, err := r.apply(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error applying billing overage cap", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *billingOverageCapResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state billingOverageCapModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	profile, err := r.client.GetBillingPricing(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading billing pricing profile", err.Error())
		return
	}

	next := flattenBillingOverageCapProfile(profile, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *billingOverageCapResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan billingOverageCapModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, err := r.apply(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error updating billing overage cap", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *billingOverageCapResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No DELETE endpoint exists; removing from Terraform state does not mutate remote billing config.
}

func (r *billingOverageCapResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

func (r *billingOverageCapResource) apply(ctx context.Context, plan billingOverageCapModel) (billingOverageCapModel, error) {
	overageCap := plan.OverageCapUSD.ValueFloat64()
	if overageCap < 0 {
		return billingOverageCapModel{}, fmt.Errorf("overage_cap_usd must be >= 0")
	}

	profile, err := r.client.UpdateBillingOverageCap(ctx, overageCap)
	if err != nil {
		return billingOverageCapModel{}, err
	}

	next := flattenBillingOverageCapProfile(profile, plan, r.tenantID)
	next.UpdatedAt = types.StringValue(time.Now().UTC().Format(time.RFC3339))
	return next, nil
}

func flattenBillingOverageCapProfile(
	profile map[string]any,
	current billingOverageCapModel,
	tenantID string,
) billingOverageCapModel {
	state := current
	state.ID = types.StringValue(tenantID)
	state.TenantID = types.StringValue(tenantID)
	state.ActiveTier = types.StringValue(tfhelpers.GetString(profile, "active_tier"))

	metered := tfhelpers.GetMap(profile, "metered_pricing")
	pilot := tfhelpers.GetMap(profile, "pilot_package")
	state.BaseMonthlyPlatformFeeUSD = types.Float64Value(tfhelpers.GetFloat64(metered, "base_monthly_platform_fee_usd"))
	state.IncludedGovernedIdentities = types.Int64Value(tfhelpers.GetInt64(metered, "included_governed_identities"))
	state.IncludedPolicyChecks = types.Int64Value(tfhelpers.GetInt64(metered, "included_policy_checks"))
	state.GovernedIdentityUSDPerMonth = types.Float64Value(tfhelpers.GetFloat64(metered, "governed_identity_usd_per_month"))
	state.PolicyChecksUSDPerMillion = types.Float64Value(tfhelpers.GetFloat64(metered, "policy_checks_usd_per_million"))
	state.OverageCapUSD = types.Float64Value(tfhelpers.GetFloat64(pilot, "overage_cap_usd"))
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(profile))
	if state.UpdatedAt.IsNull() || state.UpdatedAt.IsUnknown() || strings.TrimSpace(state.UpdatedAt.ValueString()) == "" {
		state.UpdatedAt = types.StringValue(time.Now().UTC().Format(time.RFC3339))
	}
	return state
}
