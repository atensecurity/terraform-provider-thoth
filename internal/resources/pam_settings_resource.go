package resources

import (
	"context"
	"fmt"
	"strings"

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

var _ resource.Resource = &pamSettingsResource{}
var _ resource.ResourceWithImportState = &pamSettingsResource{}

type pamSettingsResource struct {
	client   *client.Client
	tenantID string
}

type pamSettingsModel struct {
	ID                       types.String  `tfsdk:"id"`
	TenantID                 types.String  `tfsdk:"tenant_id"`
	PAMEnabled               types.Bool    `tfsdk:"pam_enabled"`
	PAMProvider              types.String  `tfsdk:"pam_provider"`
	PAMCallbackSecret        types.String  `tfsdk:"pam_callback_secret"`
	PAMRequestURL            types.String  `tfsdk:"pam_request_url"`
	PAMRequestSecret         types.String  `tfsdk:"pam_request_secret"`
	PAMRequestAuthToken      types.String  `tfsdk:"pam_request_auth_token"`
	PAMRequestTimeoutSeconds types.Float64 `tfsdk:"pam_request_timeout_seconds"`
	UpdatedAt                types.String  `tfsdk:"updated_at"`
}

func NewPAMSettingsResource() resource.Resource {
	return &pamSettingsResource{}
}

func (r *pamSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pam_settings"
}

func (r *pamSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages tenant PAM step-up integration settings.",
		Attributes: map[string]schema.Attribute{
			"id":                          schema.StringAttribute{Computed: true, Description: "Terraform resource identifier (tenant ID).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":                   schema.StringAttribute{Computed: true, Description: "Tenant ID resolved from provider configuration."},
			"pam_enabled":                 schema.BoolAttribute{Optional: true, Description: "Enable PAM step-up callback integration."},
			"pam_provider":                schema.StringAttribute{Optional: true, Description: "PAM provider slug."},
			"pam_callback_secret":         schema.StringAttribute{Optional: true, Sensitive: true, Description: "Shared secret for PAM callback validation."},
			"pam_request_url":             schema.StringAttribute{Optional: true, Description: "Outbound PAM request URL."},
			"pam_request_secret":          schema.StringAttribute{Optional: true, Sensitive: true, Description: "Outbound PAM request secret."},
			"pam_request_auth_token":      schema.StringAttribute{Optional: true, Sensitive: true, Description: "Outbound PAM auth token."},
			"pam_request_timeout_seconds": schema.Float64Attribute{Optional: true, Description: "Outbound PAM request timeout in seconds."},
			"updated_at":                  schema.StringAttribute{Computed: true, Description: "Last update timestamp returned by GovAPI."},
		},
	}
}

func (r *pamSettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *pamSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan pamSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, ok := r.apply(ctx, plan, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *pamSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state pamSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload, err := r.client.GetTenantSettings(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading PAM settings", err.Error())
		return
	}

	next := flattenPAMSettings(payload, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *pamSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan pamSettingsModel
	var state pamSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, ok := r.apply(ctx, plan, state, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *pamSettingsResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No DELETE endpoint is exposed by GovAPI for tenant settings.
}

func (r *pamSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

func (r *pamSettingsResource) apply(
	ctx context.Context,
	plan pamSettingsModel,
	prior pamSettingsModel,
	diags *diag.Diagnostics,
) (pamSettingsModel, bool) {
	existing, err := r.client.GetTenantSettings(ctx)
	if err != nil && !client.IsNotFound(err) {
		diags.AddError("Error loading current settings", err.Error())
		return pamSettingsModel{}, false
	}
	if existing == nil {
		existing = map[string]any{}
	}

	payload := cloneMap(existing)
	applyPAMSettingsPlan(&payload, plan, prior)

	updated, err := r.client.UpdateTenantSettings(ctx, payload)
	if err != nil {
		diags.AddError("Error updating PAM settings", err.Error())
		return pamSettingsModel{}, false
	}

	return flattenPAMSettings(updated, plan, r.tenantID), true
}

func applyPAMSettingsPlan(payload *map[string]any, plan pamSettingsModel, prior pamSettingsModel) {
	p := *payload
	pam := tfhelpers.GetMap(p, "pam")
	setBoolIfKnown(pam, "enabled", plan.PAMEnabled)
	setStringIfKnown(pam, "provider", plan.PAMProvider, types.StringNull())
	setStringIfKnown(pam, "callback_secret", plan.PAMCallbackSecret, prior.PAMCallbackSecret)
	setStringIfKnown(pam, "request_url", plan.PAMRequestURL, types.StringNull())
	setStringIfKnown(pam, "request_secret", plan.PAMRequestSecret, prior.PAMRequestSecret)
	setStringIfKnown(pam, "request_auth_token", plan.PAMRequestAuthToken, prior.PAMRequestAuthToken)
	if !plan.PAMRequestTimeoutSeconds.IsNull() && !plan.PAMRequestTimeoutSeconds.IsUnknown() {
		pam["request_timeout_seconds"] = plan.PAMRequestTimeoutSeconds.ValueFloat64()
	}
	p["pam"] = pam
	*payload = p
}

func flattenPAMSettings(apiPayload map[string]any, current pamSettingsModel, tenantID string) pamSettingsModel {
	state := current
	state.ID = types.StringValue(tenantID)
	state.TenantID = types.StringValue(tenantID)

	pam := tfhelpers.GetMap(apiPayload, "pam")
	state.PAMEnabled = types.BoolValue(tfhelpers.GetBool(pam, "enabled"))
	state.PAMProvider = stringValueFromMap(pam, "provider")
	if v := tfhelpers.GetString(pam, "callback_secret"); v != "" {
		state.PAMCallbackSecret = types.StringValue(v)
	}
	state.PAMRequestURL = stringValueFromMap(pam, "request_url")
	if v := tfhelpers.GetString(pam, "request_secret"); v != "" {
		state.PAMRequestSecret = types.StringValue(v)
	}
	if v := tfhelpers.GetString(pam, "request_auth_token"); v != "" {
		state.PAMRequestAuthToken = types.StringValue(v)
	}
	if _, ok := pam["request_timeout_seconds"]; ok {
		state.PAMRequestTimeoutSeconds = types.Float64Value(tfhelpers.GetFloat64(pam, "request_timeout_seconds"))
	} else {
		state.PAMRequestTimeoutSeconds = types.Float64Null()
	}

	state.UpdatedAt = stringValueFromMap(apiPayload, "updated_at")
	return state
}
