package resources

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

// GovAPI's limits (security_settings.go, session_lifetime.go).
const (
	orgSessionTimeoutDefault = 12 * 60
	orgSessionTimeoutMin     = 15
	orgSessionTimeoutMax     = 30 * 24 * 60
	orgIPAllowlistMax        = 100
)

var _ resource.Resource = &orgSecuritySettingsResource{}
var _ resource.ResourceWithImportState = &orgSecuritySettingsResource{}

type orgSecuritySettingsResource struct {
	client   *client.Client
	tenantID string
}

type orgSecuritySettingsModel struct {
	ID                    types.String `tfsdk:"id"`
	TenantID              types.String `tfsdk:"tenant_id"`
	RequireMFA            types.Bool   `tfsdk:"require_mfa"`
	SessionTimeoutMinutes types.Int64  `tfsdk:"session_timeout_minutes"`
	IPAllowlist           types.Set    `tfsdk:"ip_allowlist"`
	UpdatedAt             types.String `tfsdk:"updated_at"`
	UpdatedBy             types.String `tfsdk:"updated_by"`
}

func NewOrgSecuritySettingsResource() resource.Resource {
	return &orgSecuritySettingsResource{}
}

func (r *orgSecuritySettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_org_security_settings"
}

func (r *orgSecuritySettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Sign-in security for the workspace: require a second factor, limit how long a sign-in lasts, " +
			"and restrict the networks people and API keys may connect from. GovAPI enforces all three. " +
			"Destroying this resource removes the policy, so none of them is enforced.",
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
			"require_mfa": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "Require a second factor on every sign-in session (dashboard, thothctl and MCP). " +
					"Sessions without one are asked to verify; API keys are not affected. Default `false`.",
			},
			"session_timeout_minutes": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(orgSessionTimeoutDefault),
				Description: "How long a sign-in lasts before people must sign in again, from 15 to 43200 (30 days). " +
					"It is an absolute lifetime, not an idle timeout. Default 720 (12 hours).",
				Validators: []validator.Int64{int64validator.Between(orgSessionTimeoutMin, orgSessionTimeoutMax)},
			},
			"ip_allowlist": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
				Description: "CIDR ranges people and API keys may connect from, at most 100. Empty allows any network. " +
					"Write each range in canonical form, such as `203.0.113.7/32` or `198.51.100.0/24`. " +
					"The list must include the address this Terraform run connects from, or GovAPI refuses it.",
				Validators: []validator.Set{
					setvalidator.SizeAtMost(orgIPAllowlistMax),
					setvalidator.ValueStringsAre(canonicalCIDRValidator{}),
				},
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Last update timestamp returned by GovAPI.",
			},
			"updated_by": schema.StringAttribute{
				Computed:    true,
				Description: "Who last saved the policy, as GovAPI recorded it.",
			},
		},
	}
}

func (r *orgSecuritySettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *orgSecuritySettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan orgSecuritySettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, ok := r.apply(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *orgSecuritySettingsResource) Read(ctx context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	out, err := r.client.GetOrgSecuritySettings(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading org security settings", err.Error())
		return
	}
	// The policy was removed outside Terraform: plan to create it again.
	if configured, ok := out["configured"].(bool); ok && !configured {
		resp.State.RemoveResource(ctx)
		return
	}
	next, diags := flattenOrgSecuritySettings(out, r.tenantID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *orgSecuritySettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan orgSecuritySettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, ok := r.apply(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

// Delete removes the saved policy, so GovAPI enforces none of it.
func (r *orgSecuritySettingsResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.DeleteOrgSecuritySettings(ctx); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Error removing org security settings", err.Error())
	}
}

func (r *orgSecuritySettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

// apply saves the whole policy: GovAPI replaces every field on PUT.
func (r *orgSecuritySettingsResource) apply(ctx context.Context, plan orgSecuritySettingsModel, diags *diag.Diagnostics) (orgSecuritySettingsModel, bool) {
	var allowlist []string
	if !plan.IPAllowlist.IsNull() && !plan.IPAllowlist.IsUnknown() {
		diags.Append(plan.IPAllowlist.ElementsAs(ctx, &allowlist, false)...)
		if diags.HasError() {
			return orgSecuritySettingsModel{}, false
		}
	}
	if allowlist == nil {
		allowlist = []string{}
	}
	payload := map[string]any{
		"require_mfa":             boolValue(plan.RequireMFA, false),
		"session_timeout_minutes": plan.SessionTimeoutMinutes.ValueInt64(),
		"ip_allowlist":            allowlist,
	}
	out, err := r.client.UpdateOrgSecuritySettings(ctx, payload)
	if err != nil {
		diags.AddError("Error saving org security settings", orgSecurityHint(err))
		return orgSecuritySettingsModel{}, false
	}
	next, flattenDiags := flattenOrgSecuritySettings(out, r.tenantID)
	diags.Append(flattenDiags...)
	return next, !diags.HasError()
}

// orgSecurityHint adds what to do for GovAPI's two safety refusals.
func orgSecurityHint(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "ip_allowlist_excludes_caller"):
		return message + "\n\nAdd the address this Terraform run connects from to ip_allowlist."
	case strings.Contains(message, "mfa_required"), strings.Contains(message, "step-up authentication"):
		return message + "\n\nUse a Thoth API key for the provider, or sign in with a recent second factor."
	}
	return message
}

func flattenOrgSecuritySettings(out map[string]any, tenantID string) (orgSecuritySettingsModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	state := orgSecuritySettingsModel{
		ID:                    types.StringValue(tenantID),
		TenantID:              types.StringValue(tenantID),
		RequireMFA:            types.BoolValue(tfhelpers.GetBool(out, "require_mfa")),
		SessionTimeoutMinutes: types.Int64Value(tfhelpers.GetInt64(out, "session_timeout_minutes")),
		UpdatedAt:             stringValueFromMap(out, "updated_at"),
		UpdatedBy:             stringValueFromMap(out, "updated_by"),
	}
	values := []attr.Value{}
	if raw, ok := out["ip_allowlist"].([]any); ok {
		for _, item := range raw {
			if s, ok := item.(string); ok && s != "" {
				values = append(values, types.StringValue(s))
			}
		}
	}
	set, d := types.SetValue(types.StringType, values)
	diags.Append(d...)
	state.IPAllowlist = set
	return state, diags
}

// canonicalCIDRValidator requires the form GovAPI stores ("203.0.113.7/32",
// "198.51.100.0/24"), so the saved list always matches the configuration.
type canonicalCIDRValidator struct{}

func (canonicalCIDRValidator) Description(context.Context) string {
	return "must be a CIDR range in canonical form, such as 203.0.113.7/32"
}

func (v canonicalCIDRValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (canonicalCIDRValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if canonical, ok := canonicalCIDR(req.ConfigValue.ValueString()); !ok {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IP range",
			fmt.Sprintf("%q is not an IP address or CIDR range.", req.ConfigValue.ValueString()))
	} else if canonical != req.ConfigValue.ValueString() {
		resp.Diagnostics.AddAttributeError(req.Path, "Write the range in canonical form",
			fmt.Sprintf("Write %q as %q, the form GovAPI stores.", req.ConfigValue.ValueString(), canonical))
	}
}

// canonicalCIDR mirrors GovAPI's normalizeIPAllowlist: a bare address becomes
// /32 or /128, a range is masked, and IPv4-mapped IPv6 becomes IPv4.
func canonicalCIDR(value string) (string, bool) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return "", false
		}
		return prefix.Masked().String(), true
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", false
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()).String(), true
}
