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

var _ resource.Resource = &governanceSettingsResource{}
var _ resource.ResourceWithImportState = &governanceSettingsResource{}

type governanceSettingsResource struct {
	client   *client.Client
	tenantID string
}

type governanceSettingsModel struct {
	ID                           types.String `tfsdk:"id"`
	TenantID                     types.String `tfsdk:"tenant_id"`
	ComplianceProfile            types.String `tfsdk:"compliance_profile"`
	RegulatoryRegimes            types.List   `tfsdk:"regulatory_regimes"`
	ShadowLow                    types.String `tfsdk:"shadow_low"`
	ShadowMedium                 types.String `tfsdk:"shadow_medium"`
	ShadowHigh                   types.String `tfsdk:"shadow_high"`
	ShadowCritical               types.String `tfsdk:"shadow_critical"`
	ToolRiskOverrides            types.Map    `tfsdk:"tool_risk_overrides"`
	SecretBrokerEnabled          types.Bool   `tfsdk:"secret_broker_enabled"`
	SecretBrokerProvider         types.String `tfsdk:"secret_broker_provider"`
	SecretBrokerStrictEndpoint   types.Bool   `tfsdk:"secret_broker_strict_endpoint_mode"`
	SecretBrokerFailOnMissing    types.Bool   `tfsdk:"secret_broker_fail_on_missing_secret"`
	SecretBrokerAllowedHosts     types.List   `tfsdk:"secret_broker_allowed_hosts"`
	SecretBrokerAuthBindingsJSON types.String `tfsdk:"secret_broker_auth_bindings_json"`
	ModelRouterEnabled           types.Bool   `tfsdk:"model_router_enabled"`
	ModelRouterDefaultProvider   types.String `tfsdk:"model_router_default_provider"`
	ModelRouterDefaultModel      types.String `tfsdk:"model_router_default_model"`
	ModelRouterAllowedProviders  types.List   `tfsdk:"model_router_allowed_providers"`
	ModelRouterAllowedModels     types.List   `tfsdk:"model_router_allowed_models"`
	ModelRouterFailoverProviders types.List   `tfsdk:"model_router_failover_providers"`
	ExtraSettingsJSON            types.String `tfsdk:"extra_settings_json"`
	UpdatedAt                    types.String `tfsdk:"updated_at"`
}

func NewGovernanceSettingsResource() resource.Resource {
	return &governanceSettingsResource{}
}

func (r *governanceSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_governance_settings"
}

func (r *governanceSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages tenant governance policy settings (compliance, risk, secret broker, model router).",
		Attributes: map[string]schema.Attribute{
			"id":                                   schema.StringAttribute{Computed: true, Description: "Terraform resource identifier (tenant ID).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":                            schema.StringAttribute{Computed: true, Description: "Tenant ID resolved from provider configuration."},
			"compliance_profile":                   schema.StringAttribute{Optional: true, Description: "Compliance profile (soc2, healthcare, financial, public_sector, privacy, ai_governance)."},
			"regulatory_regimes":                   schema.ListAttribute{Optional: true, ElementType: types.StringType, Description: "Explicit regulatory regimes for onboarding baseline auto-pack loading (for example: soc2, hipaa, gdpr, fedramp, sec_cftc). Defaults to SOC2 when unset."},
			"shadow_low":                           schema.StringAttribute{Optional: true, Description: "Default action for low risk events."},
			"shadow_medium":                        schema.StringAttribute{Optional: true, Description: "Default action for medium risk events."},
			"shadow_high":                          schema.StringAttribute{Optional: true, Description: "Default action for high risk events."},
			"shadow_critical":                      schema.StringAttribute{Optional: true, Description: "Default action for critical risk events."},
			"tool_risk_overrides":                  schema.MapAttribute{Optional: true, ElementType: types.StringType, Description: "Tool-specific risk tier overrides."},
			"secret_broker_enabled":                schema.BoolAttribute{Optional: true, Description: "Enable secret broker policy enforcement."},
			"secret_broker_provider":               schema.StringAttribute{Optional: true, Computed: true, Description: "Secret broker provider slug."},
			"secret_broker_strict_endpoint_mode":   schema.BoolAttribute{Optional: true, Description: "Require endpoint registration for secret resolution."},
			"secret_broker_fail_on_missing_secret": schema.BoolAttribute{Optional: true, Description: "Fail governed calls when referenced secret is unavailable."},
			"secret_broker_allowed_hosts":          schema.ListAttribute{Optional: true, ElementType: types.StringType, Description: "Allowed host patterns for secret broker."},
			"secret_broker_auth_bindings_json":     schema.StringAttribute{Optional: true, Description: "JSON array of auth binding objects (host_pattern, header, secret_ref, prefix)."},
			"model_router_enabled":                 schema.BoolAttribute{Optional: true, Computed: true, Description: "Enable model routing policy controls."},
			"model_router_default_provider":        schema.StringAttribute{Optional: true, Computed: true, Description: "Default model provider."},
			"model_router_default_model":           schema.StringAttribute{Optional: true, Computed: true, Description: "Default model name."},
			"model_router_allowed_providers":       schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType, Description: "Allowed model providers allowlist."},
			"model_router_allowed_models":          schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType, Description: "Allowed model names allowlist."},
			"model_router_failover_providers":      schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType, Description: "Failover provider order."},
			"extra_settings_json":                  schema.StringAttribute{Optional: true, Description: "Additional JSON object merged into the outgoing settings payload for forward compatibility."},
			"updated_at":                           schema.StringAttribute{Computed: true, Description: "Last update timestamp returned by GovAPI."},
		},
	}
}

func (r *governanceSettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *governanceSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan governanceSettingsModel
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

func (r *governanceSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state governanceSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload, err := r.client.GetTenantSettings(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading governance settings", err.Error())
		return
	}

	next := flattenGovernanceSettings(payload, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *governanceSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan governanceSettingsModel
	var state governanceSettingsModel
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

func (r *governanceSettingsResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No DELETE endpoint is exposed by GovAPI for tenant settings.
}

func (r *governanceSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

func (r *governanceSettingsResource) apply(
	ctx context.Context,
	plan governanceSettingsModel,
	prior governanceSettingsModel,
	diags *diag.Diagnostics,
) (governanceSettingsModel, bool) {
	existing, err := r.client.GetTenantSettings(ctx)
	if err != nil && !client.IsNotFound(err) {
		diags.AddError("Error loading current settings", err.Error())
		return governanceSettingsModel{}, false
	}
	if existing == nil {
		existing = map[string]any{}
	}

	payload := cloneMap(existing)
	applyGovernanceSettingsPlan(&payload, plan, diags)
	if diags.HasError() {
		return governanceSettingsModel{}, false
	}

	updated, err := r.client.UpdateTenantSettings(ctx, payload)
	if err != nil {
		diags.AddError("Error updating governance settings", err.Error())
		return governanceSettingsModel{}, false
	}

	_ = prior
	return flattenGovernanceSettings(updated, plan, r.tenantID), true
}

func applyGovernanceSettingsPlan(payload *map[string]any, plan governanceSettingsModel, diags *diag.Diagnostics) {
	p := *payload

	if !plan.ComplianceProfile.IsNull() && !plan.ComplianceProfile.IsUnknown() {
		p["compliance_profile"] = plan.ComplianceProfile.ValueString()
	}
	setListIfKnown(p, "regulatory_regimes", plan.RegulatoryRegimes, diags)
	if diags.HasError() {
		return
	}

	shadow := tfhelpers.GetMap(p, "shadow_policy")
	setStringIfKnown(shadow, "low", plan.ShadowLow, types.StringNull())
	setStringIfKnown(shadow, "medium", plan.ShadowMedium, types.StringNull())
	setStringIfKnown(shadow, "high", plan.ShadowHigh, types.StringNull())
	setStringIfKnown(shadow, "critical", plan.ShadowCritical, types.StringNull())
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

	secretBroker := tfhelpers.GetMap(p, "secret_broker")
	setBoolIfKnown(secretBroker, "enabled", plan.SecretBrokerEnabled)
	if !plan.SecretBrokerProvider.IsNull() && !plan.SecretBrokerProvider.IsUnknown() {
		secretBroker["provider"] = canonicalSecretBrokerProvider(plan.SecretBrokerProvider.ValueString())
	}
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

func flattenGovernanceSettings(apiPayload map[string]any, current governanceSettingsModel, tenantID string) governanceSettingsModel {
	state := current
	state.ID = types.StringValue(tenantID)
	state.TenantID = types.StringValue(tenantID)
	state.ComplianceProfile = stringValueFromMap(apiPayload, "compliance_profile")
	state.RegulatoryRegimes = tfhelpers.StringSliceValue(tfhelpers.GetStringSlice(apiPayload, "regulatory_regimes"))

	shadow := tfhelpers.GetMap(apiPayload, "shadow_policy")
	state.ShadowLow = stringValueFromMap(shadow, "low")
	state.ShadowMedium = stringValueFromMap(shadow, "medium")
	state.ShadowHigh = stringValueFromMap(shadow, "high")
	state.ShadowCritical = stringValueFromMap(shadow, "critical")
	state.ToolRiskOverrides = tfhelpers.StringMapValue(tfhelpers.GetStringMap(apiPayload, "tool_risk_overrides"))

	secretBroker := tfhelpers.GetMap(apiPayload, "secret_broker")
	state.SecretBrokerEnabled = types.BoolValue(tfhelpers.GetBool(secretBroker, "enabled"))
	if provider := canonicalSecretBrokerProvider(tfhelpers.GetString(secretBroker, "provider")); provider == "" {
		state.SecretBrokerProvider = types.StringNull()
	} else {
		state.SecretBrokerProvider = types.StringValue(provider)
	}
	state.SecretBrokerStrictEndpoint = types.BoolValue(tfhelpers.GetBool(secretBroker, "strict_endpoint_mode"))
	state.SecretBrokerFailOnMissing = types.BoolValue(tfhelpers.GetBool(secretBroker, "fail_on_missing_secret"))
	state.SecretBrokerAllowedHosts = tfhelpers.StringSliceValue(tfhelpers.GetStringSlice(secretBroker, "allowed_hosts"))
	state.SecretBrokerAuthBindingsJSON = types.StringValue(tfhelpers.ToJSONArrayString(secretBroker["auth_bindings"]))

	if rawModelRouter, exists := apiPayload["model_router"]; exists && rawModelRouter != nil {
		modelRouter := tfhelpers.GetMap(apiPayload, "model_router")
		state.ModelRouterEnabled = types.BoolValue(tfhelpers.GetBool(modelRouter, "enabled"))
		state.ModelRouterDefaultProvider = stringValueFromMap(modelRouter, "default_provider")
		state.ModelRouterDefaultModel = stringValueFromMap(modelRouter, "default_model")
		state.ModelRouterAllowedProviders = tfhelpers.StringSliceValue(tfhelpers.GetStringSlice(modelRouter, "allowed_providers"))
		state.ModelRouterAllowedModels = tfhelpers.StringSliceValue(tfhelpers.GetStringSlice(modelRouter, "allowed_models"))
		state.ModelRouterFailoverProviders = tfhelpers.StringSliceValue(tfhelpers.GetStringSlice(modelRouter, "failover_providers"))
	}

	state.UpdatedAt = stringValueFromMap(apiPayload, "updated_at")
	return state
}

func canonicalSecretBrokerProvider(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "null":
		return ""
	case "aws-secrets-manager", "aws_secrets_manager":
		return "aws_secrets_manager"
	default:
		return strings.TrimSpace(raw)
	}
}
