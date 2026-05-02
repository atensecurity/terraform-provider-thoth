package resources

import (
	"context"
	"encoding/json"
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

var _ resource.Resource = &tenantSettingsResource{}
var _ resource.ResourceWithImportState = &tenantSettingsResource{}

type tenantSettingsResource struct {
	client   *client.Client
	tenantID string
}

type tenantSettingsModel struct {
	ID                           types.String  `tfsdk:"id"`
	TenantID                     types.String  `tfsdk:"tenant_id"`
	ComplianceProfile            types.String  `tfsdk:"compliance_profile"`
	ShadowLow                    types.String  `tfsdk:"shadow_low"`
	ShadowMedium                 types.String  `tfsdk:"shadow_medium"`
	ShadowHigh                   types.String  `tfsdk:"shadow_high"`
	ShadowCritical               types.String  `tfsdk:"shadow_critical"`
	ToolRiskOverrides            types.Map     `tfsdk:"tool_risk_overrides"`
	WebhookEnabled               types.Bool    `tfsdk:"webhook_enabled"`
	WebhookURL                   types.String  `tfsdk:"webhook_url"`
	WebhookSecret                types.String  `tfsdk:"webhook_secret"`
	SIEMProvider                 types.String  `tfsdk:"siem_provider"`
	SIEMWebhookEnabled           types.Bool    `tfsdk:"siem_webhook_enabled"`
	SIEMWebhookURL               types.String  `tfsdk:"siem_webhook_url"`
	SIEMWebhookSecret            types.String  `tfsdk:"siem_webhook_secret"`
	SIEMWebhookProvider          types.String  `tfsdk:"siem_webhook_provider"`
	PAMEnabled                   types.Bool    `tfsdk:"pam_enabled"`
	PAMProvider                  types.String  `tfsdk:"pam_provider"`
	PAMCallbackSecret            types.String  `tfsdk:"pam_callback_secret"`
	PAMRequestURL                types.String  `tfsdk:"pam_request_url"`
	PAMRequestSecret             types.String  `tfsdk:"pam_request_secret"`
	PAMRequestAuthToken          types.String  `tfsdk:"pam_request_auth_token"`
	PAMRequestTimeoutSeconds     types.Float64 `tfsdk:"pam_request_timeout_seconds"`
	SecretBrokerEnabled          types.Bool    `tfsdk:"secret_broker_enabled"`
	SecretBrokerProvider         types.String  `tfsdk:"secret_broker_provider"`
	SecretBrokerStrictEndpoint   types.Bool    `tfsdk:"secret_broker_strict_endpoint_mode"`
	SecretBrokerFailOnMissing    types.Bool    `tfsdk:"secret_broker_fail_on_missing_secret"`
	SecretBrokerAllowedHosts     types.List    `tfsdk:"secret_broker_allowed_hosts"`
	SecretBrokerAuthBindingsJSON types.String  `tfsdk:"secret_broker_auth_bindings_json"`
	ModelRouterEnabled           types.Bool    `tfsdk:"model_router_enabled"`
	ModelRouterDefaultProvider   types.String  `tfsdk:"model_router_default_provider"`
	ModelRouterDefaultModel      types.String  `tfsdk:"model_router_default_model"`
	ModelRouterAllowedProviders  types.List    `tfsdk:"model_router_allowed_providers"`
	ModelRouterAllowedModels     types.List    `tfsdk:"model_router_allowed_models"`
	ModelRouterFailoverProviders types.List    `tfsdk:"model_router_failover_providers"`
	ExtraSettingsJSON            types.String  `tfsdk:"extra_settings_json"`
	TestWebhookOnApply           types.Bool    `tfsdk:"test_webhook_on_apply"`
	UpdatedAt                    types.String  `tfsdk:"updated_at"`
}

func NewTenantSettingsResource() resource.Resource {
	return &tenantSettingsResource{}
}

func (r *tenantSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant_settings"
}

func (r *tenantSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages tenant-wide Thoth governance settings.",
		Attributes: map[string]schema.Attribute{
			"id":                                   schema.StringAttribute{Computed: true, Description: "Terraform resource identifier (tenant ID).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":                            schema.StringAttribute{Computed: true, Description: "Tenant ID resolved from provider configuration."},
			"compliance_profile":                   schema.StringAttribute{Optional: true, Description: "Compliance profile (soc2, healthcare, financial, public_sector, privacy, ai_governance)."},
			"shadow_low":                           schema.StringAttribute{Optional: true, Description: "Default action for low risk events."},
			"shadow_medium":                        schema.StringAttribute{Optional: true, Description: "Default action for medium risk events."},
			"shadow_high":                          schema.StringAttribute{Optional: true, Description: "Default action for high risk events."},
			"shadow_critical":                      schema.StringAttribute{Optional: true, Description: "Default action for critical risk events."},
			"tool_risk_overrides":                  schema.MapAttribute{Optional: true, ElementType: types.StringType, Description: "Tool-specific risk tier overrides."},
			"webhook_enabled":                      schema.BoolAttribute{Optional: true, Description: "Enable outbound webhook delivery."},
			"webhook_url":                          schema.StringAttribute{Optional: true, Description: "Outbound webhook URL."},
			"webhook_secret":                       schema.StringAttribute{Optional: true, Sensitive: true, Description: "Webhook signing secret."},
			"siem_provider":                        schema.StringAttribute{Optional: true, Description: "SIEM provider slug."},
			"siem_webhook_enabled":                 schema.BoolAttribute{Optional: true, Description: "Enable SIEM webhook delivery."},
			"siem_webhook_url":                     schema.StringAttribute{Optional: true, Description: "SIEM webhook URL."},
			"siem_webhook_secret":                  schema.StringAttribute{Optional: true, Sensitive: true, Description: "SIEM webhook signing secret."},
			"siem_webhook_provider":                schema.StringAttribute{Optional: true, Description: "SIEM webhook provider slug."},
			"pam_enabled":                          schema.BoolAttribute{Optional: true, Description: "Enable PAM step-up callback integration."},
			"pam_provider":                         schema.StringAttribute{Optional: true, Description: "PAM provider slug."},
			"pam_callback_secret":                  schema.StringAttribute{Optional: true, Sensitive: true, Description: "Shared secret for PAM callback validation."},
			"pam_request_url":                      schema.StringAttribute{Optional: true, Description: "Outbound PAM request URL."},
			"pam_request_secret":                   schema.StringAttribute{Optional: true, Sensitive: true, Description: "Outbound PAM request secret."},
			"pam_request_auth_token":               schema.StringAttribute{Optional: true, Sensitive: true, Description: "Outbound PAM auth token."},
			"pam_request_timeout_seconds":          schema.Float64Attribute{Optional: true, Description: "Outbound PAM request timeout in seconds."},
			"secret_broker_enabled":                schema.BoolAttribute{Optional: true, Description: "Enable secret broker policy enforcement."},
			"secret_broker_provider":               schema.StringAttribute{Optional: true, Description: "Secret broker provider slug."},
			"secret_broker_strict_endpoint_mode":   schema.BoolAttribute{Optional: true, Description: "Require endpoint registration for secret resolution."},
			"secret_broker_fail_on_missing_secret": schema.BoolAttribute{Optional: true, Description: "Fail governed calls when referenced secret is unavailable."},
			"secret_broker_allowed_hosts":          schema.ListAttribute{Optional: true, ElementType: types.StringType, Description: "Allowed host patterns for secret broker."},
			"secret_broker_auth_bindings_json":     schema.StringAttribute{Optional: true, Description: "JSON array of auth binding objects (host_pattern, header, secret_ref, prefix)."},
			"model_router_enabled":                 schema.BoolAttribute{Optional: true, Description: "Enable model routing policy controls."},
			"model_router_default_provider":        schema.StringAttribute{Optional: true, Description: "Default model provider."},
			"model_router_default_model":           schema.StringAttribute{Optional: true, Description: "Default model name."},
			"model_router_allowed_providers":       schema.ListAttribute{Optional: true, ElementType: types.StringType, Description: "Allowed model providers allowlist."},
			"model_router_allowed_models":          schema.ListAttribute{Optional: true, ElementType: types.StringType, Description: "Allowed model names allowlist."},
			"model_router_failover_providers":      schema.ListAttribute{Optional: true, ElementType: types.StringType, Description: "Failover provider order."},
			"extra_settings_json":                  schema.StringAttribute{Optional: true, Description: "Additional JSON object merged into the outgoing settings payload for forward compatibility."},
			"test_webhook_on_apply":                schema.BoolAttribute{Optional: true, Description: "Run webhook test endpoint after applying settings."},
			"updated_at":                           schema.StringAttribute{Computed: true, Description: "Last update timestamp returned by GovAPI."},
		},
	}
}

func (r *tenantSettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *tenantSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan tenantSettingsModel
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

func (r *tenantSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state tenantSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload, err := r.client.GetTenantSettings(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading tenant settings", err.Error())
		return
	}

	next := flattenTenantSettings(payload, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *tenantSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tenantSettingsModel
	var state tenantSettingsModel
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

func (r *tenantSettingsResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No DELETE endpoint is exposed by GovAPI for tenant settings.
}

func (r *tenantSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

func (r *tenantSettingsResource) apply(
	ctx context.Context,
	plan tenantSettingsModel,
	prior tenantSettingsModel,
	diags *diag.Diagnostics,
) (tenantSettingsModel, bool) {
	existing, err := r.client.GetTenantSettings(ctx)
	if err != nil && !client.IsNotFound(err) {
		diags.AddError("Error loading current settings", err.Error())
		return tenantSettingsModel{}, false
	}
	if existing == nil {
		existing = map[string]any{}
	}

	payload := cloneMap(existing)
	applyTenantSettingsPlan(&payload, plan, prior, diags)
	if diags.HasError() {
		return tenantSettingsModel{}, false
	}

	updated, err := r.client.UpdateTenantSettings(ctx, payload)
	if err != nil {
		diags.AddError("Error updating tenant settings", err.Error())
		return tenantSettingsModel{}, false
	}

	if boolValue(plan.TestWebhookOnApply, false) {
		result, err := r.client.TestWebhook(ctx)
		if err != nil {
			diags.AddWarning("Webhook test failed", err.Error())
		} else if status := strings.ToLower(tfhelpers.GetString(result, "status")); status != "delivered" {
			diags.AddWarning("Webhook test did not report delivered", tfhelpers.ToJSONString(result))
		}
	}

	return flattenTenantSettings(updated, plan, r.tenantID), true
}

func applyTenantSettingsPlan(payload *map[string]any, plan tenantSettingsModel, prior tenantSettingsModel, diags *diag.Diagnostics) {
	p := *payload
	p["tenant_id"] = prior.TenantID.ValueString()

	if !plan.ComplianceProfile.IsNull() && !plan.ComplianceProfile.IsUnknown() {
		p["compliance_profile"] = plan.ComplianceProfile.ValueString()
	}
	if _, ok := p["compliance_profile"]; !ok {
		p["compliance_profile"] = "soc2"
	}

	shadow := tfhelpers.GetMap(p, "shadow_policy")
	setStringIfKnown(shadow, "low", plan.ShadowLow, types.StringValue("allow"))
	setStringIfKnown(shadow, "medium", plan.ShadowMedium, types.StringValue("step_up"))
	setStringIfKnown(shadow, "high", plan.ShadowHigh, types.StringValue("block"))
	setStringIfKnown(shadow, "critical", plan.ShadowCritical, types.StringValue("block"))
	p["shadow_policy"] = shadow

	if !plan.ToolRiskOverrides.IsNull() && !plan.ToolRiskOverrides.IsUnknown() {
		values := map[string]string{}
		diags.Append(plan.ToolRiskOverrides.ElementsAs(context.Background(), &values, false)...)
		if diags.HasError() {
			return
		}
		mapped := make(map[string]any, len(values))
		for k, v := range values {
			mapped[k] = v
		}
		p["tool_risk_overrides"] = mapped
	}

	webhook := tfhelpers.GetMap(p, "webhook")
	setBoolIfKnown(webhook, "enabled", plan.WebhookEnabled)
	setStringIfKnown(webhook, "url", plan.WebhookURL, types.StringNull())
	setStringIfKnown(webhook, "secret", plan.WebhookSecret, prior.WebhookSecret)
	p["webhook"] = webhook

	siem := tfhelpers.GetMap(p, "siem")
	setStringIfKnown(siem, "provider", plan.SIEMProvider, types.StringNull())
	siemWebhook := tfhelpers.GetMap(siem, "webhook")
	setBoolIfKnown(siemWebhook, "enabled", plan.SIEMWebhookEnabled)
	setStringIfKnown(siemWebhook, "url", plan.SIEMWebhookURL, types.StringNull())
	setStringIfKnown(siemWebhook, "secret", plan.SIEMWebhookSecret, prior.SIEMWebhookSecret)
	setStringIfKnown(siemWebhook, "provider", plan.SIEMWebhookProvider, types.StringNull())
	siem["webhook"] = siemWebhook
	p["siem"] = siem

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

	secretBroker := tfhelpers.GetMap(p, "secret_broker")
	setBoolIfKnown(secretBroker, "enabled", plan.SecretBrokerEnabled)
	setStringIfKnown(secretBroker, "provider", plan.SecretBrokerProvider, types.StringNull())
	setBoolIfKnown(secretBroker, "strict_endpoint_mode", plan.SecretBrokerStrictEndpoint)
	setBoolIfKnown(secretBroker, "fail_on_missing_secret", plan.SecretBrokerFailOnMissing)
	if !plan.SecretBrokerAllowedHosts.IsNull() && !plan.SecretBrokerAllowedHosts.IsUnknown() {
		var hosts []string
		diags.Append(plan.SecretBrokerAllowedHosts.ElementsAs(context.Background(), &hosts, false)...)
		if diags.HasError() {
			return
		}
		arr := make([]any, 0, len(hosts))
		for _, h := range hosts {
			arr = append(arr, h)
		}
		secretBroker["allowed_hosts"] = arr
	}
	if !plan.SecretBrokerAuthBindingsJSON.IsNull() && !plan.SecretBrokerAuthBindingsJSON.IsUnknown() {
		rows, err := tfhelpers.ParseJSONArray(plan.SecretBrokerAuthBindingsJSON.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("secret_broker_auth_bindings_json"), "Invalid JSON", err.Error())
			return
		}
		arr := make([]any, 0, len(rows))
		for _, row := range rows {
			arr = append(arr, row)
		}
		secretBroker["auth_bindings"] = arr
	}
	p["secret_broker"] = secretBroker

	modelRouter := tfhelpers.GetMap(p, "model_router")
	setBoolIfKnown(modelRouter, "enabled", plan.ModelRouterEnabled)
	setStringIfKnown(modelRouter, "default_provider", plan.ModelRouterDefaultProvider, types.StringNull())
	setStringIfKnown(modelRouter, "default_model", plan.ModelRouterDefaultModel, types.StringNull())
	setListIfKnown(modelRouter, "allowed_providers", plan.ModelRouterAllowedProviders, diags)
	setListIfKnown(modelRouter, "allowed_models", plan.ModelRouterAllowedModels, diags)
	setListIfKnown(modelRouter, "failover_providers", plan.ModelRouterFailoverProviders, diags)
	p["model_router"] = modelRouter

	if !plan.ExtraSettingsJSON.IsNull() && !plan.ExtraSettingsJSON.IsUnknown() {
		extra, err := tfhelpers.ParseJSONObject(plan.ExtraSettingsJSON.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("extra_settings_json"), "Invalid JSON", err.Error())
			return
		}
		deepMergeMap(p, extra)
	}

	*payload = p
}

func flattenTenantSettings(apiPayload map[string]any, current tenantSettingsModel, tenantID string) tenantSettingsModel {
	state := current
	state.ID = types.StringValue(tenantID)
	state.TenantID = types.StringValue(tenantID)
	state.ComplianceProfile = stringValueFromMap(apiPayload, "compliance_profile")

	shadow := tfhelpers.GetMap(apiPayload, "shadow_policy")
	state.ShadowLow = stringValueFromMap(shadow, "low")
	state.ShadowMedium = stringValueFromMap(shadow, "medium")
	state.ShadowHigh = stringValueFromMap(shadow, "high")
	state.ShadowCritical = stringValueFromMap(shadow, "critical")

	state.ToolRiskOverrides = tfhelpers.StringMapValue(tfhelpers.GetStringMap(apiPayload, "tool_risk_overrides"))

	webhook := tfhelpers.GetMap(apiPayload, "webhook")
	state.WebhookEnabled = types.BoolValue(tfhelpers.GetBool(webhook, "enabled"))
	state.WebhookURL = stringValueFromMap(webhook, "url")
	if v := tfhelpers.GetString(webhook, "secret"); v != "" {
		state.WebhookSecret = types.StringValue(v)
	}

	siem := tfhelpers.GetMap(apiPayload, "siem")
	state.SIEMProvider = stringValueFromMap(siem, "provider")
	siemWebhook := tfhelpers.GetMap(siem, "webhook")
	state.SIEMWebhookEnabled = types.BoolValue(tfhelpers.GetBool(siemWebhook, "enabled"))
	state.SIEMWebhookURL = stringValueFromMap(siemWebhook, "url")
	if v := tfhelpers.GetString(siemWebhook, "secret"); v != "" {
		state.SIEMWebhookSecret = types.StringValue(v)
	}
	state.SIEMWebhookProvider = stringValueFromMap(siemWebhook, "provider")

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
	state.PAMRequestTimeoutSeconds = types.Float64Value(tfhelpers.GetFloat64(pam, "request_timeout_seconds"))

	secretBroker := tfhelpers.GetMap(apiPayload, "secret_broker")
	state.SecretBrokerEnabled = types.BoolValue(tfhelpers.GetBool(secretBroker, "enabled"))
	state.SecretBrokerProvider = stringValueFromMap(secretBroker, "provider")
	state.SecretBrokerStrictEndpoint = types.BoolValue(tfhelpers.GetBool(secretBroker, "strict_endpoint_mode"))
	state.SecretBrokerFailOnMissing = types.BoolValue(tfhelpers.GetBool(secretBroker, "fail_on_missing_secret"))
	state.SecretBrokerAllowedHosts = tfhelpers.StringSliceValue(tfhelpers.GetStringSlice(secretBroker, "allowed_hosts"))
	state.SecretBrokerAuthBindingsJSON = types.StringValue(tfhelpers.ToJSONArrayString(secretBroker["auth_bindings"]))

	modelRouter := tfhelpers.GetMap(apiPayload, "model_router")
	state.ModelRouterEnabled = types.BoolValue(tfhelpers.GetBool(modelRouter, "enabled"))
	state.ModelRouterDefaultProvider = stringValueFromMap(modelRouter, "default_provider")
	state.ModelRouterDefaultModel = stringValueFromMap(modelRouter, "default_model")
	state.ModelRouterAllowedProviders = tfhelpers.StringSliceValue(tfhelpers.GetStringSlice(modelRouter, "allowed_providers"))
	state.ModelRouterAllowedModels = tfhelpers.StringSliceValue(tfhelpers.GetStringSlice(modelRouter, "allowed_models"))
	state.ModelRouterFailoverProviders = tfhelpers.StringSliceValue(tfhelpers.GetStringSlice(modelRouter, "failover_providers"))

	state.UpdatedAt = stringValueFromMap(apiPayload, "updated_at")
	return state
}

func cloneMap(in map[string]any) map[string]any {
	b, err := json.Marshal(in)
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func deepMergeMap(dst map[string]any, src map[string]any) {
	for k, v := range src {
		if nested, ok := v.(map[string]any); ok {
			existing, ok := dst[k].(map[string]any)
			if !ok {
				dst[k] = cloneMap(nested)
				continue
			}
			deepMergeMap(existing, nested)
			dst[k] = existing
			continue
		}
		dst[k] = v
	}
}

func boolValue(v types.Bool, fallback bool) bool {
	if v.IsNull() || v.IsUnknown() {
		return fallback
	}
	return v.ValueBool()
}

func setStringIfKnown(target map[string]any, key string, value types.String, fallback types.String) {
	if !value.IsNull() && !value.IsUnknown() {
		target[key] = value.ValueString()
		return
	}
	if !fallback.IsNull() && !fallback.IsUnknown() {
		target[key] = fallback.ValueString()
	}
}

func setBoolIfKnown(target map[string]any, key string, value types.Bool) {
	if value.IsNull() || value.IsUnknown() {
		return
	}
	target[key] = value.ValueBool()
}

func setListIfKnown(target map[string]any, key string, value types.List, diags *diag.Diagnostics) {
	if value.IsNull() || value.IsUnknown() {
		return
	}
	var items []string
	diags.Append(value.ElementsAs(context.Background(), &items, false)...)
	if diags.HasError() {
		return
	}
	arr := make([]any, 0, len(items))
	for _, item := range items {
		arr = append(arr, item)
	}
	target[key] = arr
}

func stringValueFromMap(m map[string]any, key string) types.String {
	value := strings.TrimSpace(tfhelpers.GetString(m, key))
	if value == "" {
		return types.StringNull()
	}
	return types.StringValue(value)
}
