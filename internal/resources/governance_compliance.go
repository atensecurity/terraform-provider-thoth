package resources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/atensecurity/terraform-provider-thoth/internal/compliancecatalogue"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.ResourceWithModifyPlan = &governanceSettingsResource{}
var _ resource.ResourceWithValidateConfig = &governanceSettingsResource{}
var coverageType = types.ObjectType{AttrTypes: map[string]attr.Type{"enforced": types.Int64Type, "evidence_gap": types.Int64Type, "not_action_time": types.Int64Type, "total": types.Int64Type}}

func complianceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"declared_regulatory_regimes": schema.SetAttribute{Optional: true, ElementType: types.StringType, Description: "Explicit executable compliance declaration for all current and future tenant agents. Case and separators are ignored. Removing a managed declaration or setting [] clears it. Legacy profile defaults never activate this binding."},
		"compliance_enforcement_mode": schema.StringAttribute{Optional: true, Description: "Required with a nonempty declaration: observe evaluates and records advisory findings while preserving independent authorization; enforce adds non-grantable restrictions for DENY, STEP_UP and evidence-based UNRESOLVED. Changing mode affects every tenant agent within 1000 ms. Structurally unserved regimes report coverage gaps and add no action restriction."},
		"canonical_regimes":           schema.SetAttribute{Computed: true, ElementType: types.StringType, Description: "Canonical declared regimes. Known during planning for known declarations."},
		"compliance_coverage": schema.MapNestedAttribute{Computed: true, Description: "Per-regime author classifications from the pinned executable catalogue, available before first apply. These counts are not a regulatory conformance assessment.", NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"enforced":        schema.Int64Attribute{Computed: true, Description: "Action-time controls with executable predicates."},
			"evidence_gap":    schema.Int64Attribute{Computed: true, Description: "Controls classified as evidence gaps."},
			"not_action_time": schema.Int64Attribute{Computed: true, Description: "Controls outside action-time enforcement."},
			"total":           schema.Int64Attribute{Computed: true, Description: "Total classified controls."},
		}}},
		"regimes_without_controls":    schema.SetAttribute{Computed: true, ElementType: types.StringType, Description: "Declared regimes with no executable controls. These are coverage gaps, never a clean result or a per-action restriction."},
		"compliance_catalogue_sha256": schema.StringAttribute{Computed: true, Description: "Pinned catalogue identity. Apply fails before mutation if the running catalogue differs."},
		"compliance_evaluator_sha256": schema.StringAttribute{Computed: true, Description: "Pinned evaluator identity, checked before mutation."},
		"compliance_revision":         schema.Int64Attribute{Computed: true, Description: "Revision used for optimistic concurrency. A stale apply or destroy fails without replacing a newer declaration."},
		"propagation_max_ms":          schema.Int64Attribute{Computed: true, Description: "Maximum positive cache lifetime for declaration changes: 1000 milliseconds."},
	}
}

// Unknown elements must defer validation until their values are resolved.
func declarationValues(ctx context.Context, value types.Set) ([]string, bool, error) {
	if value.IsUnknown() {
		return nil, false, nil
	}
	if value.IsNull() {
		return []string{}, true, nil
	}
	result := []string{}
	allKnown := true
	for _, elem := range value.Elements() {
		str, ok := elem.(types.String)
		if !ok || str.IsNull() {
			return nil, true, fmt.Errorf("regime names must be non-null strings")
		}
		if str.IsUnknown() {
			allKnown = false
			continue
		}
		result = append(result, str.ValueString())
	}
	canonical, err := compliancecatalogue.CanonicalizeSet(result)
	return canonical, allKnown, err
}
func validateComplianceConfig(ctx context.Context, data governanceSettingsModel, diags *diag.Diagnostics) {
	values, known, err := declarationValues(ctx, data.DeclaredRegulatoryRegimes)
	if err != nil {
		diags.AddAttributeError(path.Root("declared_regulatory_regimes"), "Invalid compliance declaration", err.Error())
	}
	mode := data.ComplianceEnforcementMode
	if !mode.IsUnknown() && !mode.IsNull() && mode.ValueString() != "observe" && mode.ValueString() != "enforce" {
		diags.AddAttributeError(path.Root("compliance_enforcement_mode"), "Invalid compliance mode", "Accepted values: observe, enforce.")
	}
	if known && err == nil && !mode.IsUnknown() {
		if len(values) > 0 && mode.IsNull() {
			diags.AddAttributeError(path.Root("compliance_enforcement_mode"), "Explicit mode required", "Set observe or enforce when declaring regimes; removing mode while regimes remain active is not allowed.")
		}
		if len(values) == 0 && !mode.IsNull() {
			diags.AddAttributeError(path.Root("compliance_enforcement_mode"), "Mode requires regimes", "Remove the mode when removing or clearing declared_regulatory_regimes.")
		}
	}
	if !data.ExtraSettingsJSON.IsNull() && !data.ExtraSettingsJSON.IsUnknown() {
		extra, err := tfhelpers.ParseJSONObject(data.ExtraSettingsJSON.ValueString())
		if err == nil {
			err = validateComplianceExtra(extra)
		}
		if err != nil {
			diags.AddAttributeError(path.Root("extra_settings_json"), "Invalid extra settings", err.Error())
		}
	}
}
func (r *governanceSettingsResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data governanceSettingsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if !resp.Diagnostics.HasError() {
		validateComplianceConfig(ctx, data, &resp.Diagnostics)
	}
}
func (r *governanceSettingsResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var data governanceSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The tenant is resolved from provider configuration, never from extra JSON.
	if r.tenantID != "" {
		data.TenantID = types.StringValue(r.tenantID)
	}
	if !req.State.Raw.IsNull() {
		var prior, config governanceSettingsModel
		resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
		if resp.Diagnostics.HasError() {
			return
		}
		stabilizeGovernanceComputedPlan(&data, config, prior)
	}
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &data)...)
	validateComplianceConfig(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	values, known, _ := declarationValues(ctx, data.DeclaredRegulatoryRegimes)
	if !known {
		return
	}
	// An omitted, never-managed declaration does not adopt an out-of-band binding.
	if data.DeclaredRegulatoryRegimes.IsNull() {
		if req.State.Raw.IsNull() {
			return
		}
		var prior governanceSettingsModel
		resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
		if prior.DeclaredRegulatoryRegimes.IsNull() {
			return
		}
	}
	setCompliancePreview(&data, values)
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &data)...)
	if len(data.RegimesWithoutControls.Elements()) > 0 {
		resp.Diagnostics.AddWarning("Declared regimes have no executable controls", "See regimes_without_controls. These regimes contribute coverage gaps, not per-action restrictions. This catalogue makes no regulatory conformance claim.")
	}
	if data.ComplianceEnforcementMode.ValueString() == "enforce" {
		resp.Diagnostics.AddWarning("Tenant-wide compliance enforcement", "This plan enables non-grantable compliance restrictions for all current and future agents within 1000 ms. Evidence-based UNRESOLVED blocks; structural coverage gaps do not. Independent authorization restrictions remain in force in either mode.")
	}
}
func setCompliancePreview(data *governanceSettingsModel, values []string) {
	counts, gaps := compliancecatalogue.Coverage(values)
	data.CanonicalRegimes, _ = types.SetValueFrom(context.Background(), types.StringType, values)
	data.RegimesWithoutControls, _ = types.SetValueFrom(context.Background(), types.StringType, gaps)
	entries := map[string]attr.Value{}
	for regime, c := range counts {
		entries[regime] = types.ObjectValueMust(coverageType.AttrTypes, map[string]attr.Value{"enforced": types.Int64Value(int64(c.Enforced)), "evidence_gap": types.Int64Value(int64(c.EvidenceGap)), "not_action_time": types.Int64Value(int64(c.NotActionTime)), "total": types.Int64Value(int64(c.Total))})
	}
	data.ComplianceCoverage = types.MapValueMust(coverageType, entries)
	contract := compliancecatalogue.Manifest()
	data.ComplianceCatalogueSHA256 = types.StringValue(contract.CatalogueSHA256)
	data.ComplianceEvaluatorSHA256 = types.StringValue(contract.EvaluatorSHA256)
	data.PropagationMaxMS = types.Int64Value(1000)
}
func isComplianceField(key string) bool {
	key = strings.ToLower(key)
	return key == "declared_regulatory_regimes" || key == "regimes_without_controls" || key == "propagation_max_ms" || key == "canonical_regimes" || key == "compliance" || strings.HasPrefix(key, "compliance_") && key != "compliance_profile"
}
func stripComplianceFields(payload map[string]any) {
	for key := range payload {
		if isComplianceField(key) {
			delete(payload, key)
		}
	}
}
func validateComplianceExtra(extra map[string]any) error {
	for key := range extra {
		if isComplianceField(key) {
			return fmt.Errorf("%s is reserved; use the typed declaration and mode fields", key)
		}
	}
	return nil
}

func (r *governanceSettingsResource) applyComplianceMutation(ctx context.Context, payload map[string]any, plan, prior governanceSettingsModel, diags *diag.Diagnostics) bool {
	validateComplianceConfig(ctx, plan, diags)
	if diags.HasError() {
		return false
	}
	if plan.DeclaredRegulatoryRegimes.IsNull() && prior.DeclaredRegulatoryRegimes.IsNull() {
		return true
	}
	values, known, err := declarationValues(ctx, plan.DeclaredRegulatoryRegimes)
	if !known || err != nil || plan.ComplianceEnforcementMode.IsUnknown() {
		diags.AddError("Unresolved compliance configuration", "Declaration and mode must be known before apply.")
		return false
	}
	capability, err := r.client.GetComplianceCatalogue(ctx)
	if err != nil {
		diags.AddError("Compliance capability unavailable", err.Error())
		return false
	}
	manifest := compliancecatalogue.Manifest()
	if capability["catalogue_sha256"] != manifest.CatalogueSHA256 || capability["evaluator_sha256"] != manifest.EvaluatorSHA256 || capability["transactional_declarations_supported"] != true {
		diags.AddError("Compliance capability mismatch", "The running enforcer must match this provider's catalogue and evaluator and support transactional declarations. No settings were changed; reconcile versions before applying.")
		return false
	}
	revision := prior.ComplianceRevision.ValueInt64()
	if !prior.DeclaredRegulatoryRegimes.IsNull() && (prior.ComplianceRevision.IsNull() || prior.ComplianceRevision.IsUnknown()) {
		diags.AddError("Missing compliance revision", "Refresh the managed declaration before changing or destroying it.")
		return false
	}
	payload["declared_regulatory_regimes"] = values
	if len(values) == 0 {
		payload["compliance_enforcement_mode"] = nil
	} else {
		payload["compliance_enforcement_mode"] = plan.ComplianceEnforcementMode.ValueString()
	}
	payload["compliance_expected_revision"] = revision
	payload["compliance_catalogue_sha256"] = manifest.CatalogueSHA256
	payload["compliance_evaluator_sha256"] = manifest.EvaluatorSHA256
	// Stable across transport retries and an ambiguous acknowledgement; scoped by
	// tenant and expected revision so a later change cannot replay an older request.
	identity, _ := json.Marshal([]any{r.tenantID, revision, values, payload["compliance_enforcement_mode"], manifest.CatalogueSHA256, manifest.EvaluatorSHA256})
	hash := sha256.Sum256(identity)
	payload["compliance_request_id"] = "terraform-" + hex.EncodeToString(hash[:])
	return true
}
func flattenComplianceSettings(payload map[string]any, state *governanceSettingsModel) {
	values := tfhelpers.GetStringSlice(payload, "declared_regulatory_regimes")
	setCompliancePreview(state, values)
	// Keep configured aliases while semantically equal; reflect genuine external
	// drift only for an already managed declaration. Import does not take ownership.
	if !state.DeclaredRegulatoryRegimes.IsNull() {
		current, known, err := declarationValues(context.Background(), state.DeclaredRegulatoryRegimes)
		canonical, _ := compliancecatalogue.CanonicalizeSet(values)
		left, _ := json.Marshal(current)
		right, _ := json.Marshal(canonical)
		if err != nil || !known || string(left) != string(right) {
			state.DeclaredRegulatoryRegimes, _ = types.SetValueFrom(context.Background(), types.StringType, values)
		}
		state.ComplianceEnforcementMode = stringValueFromMap(payload, "compliance_enforcement_mode")
	}
	// Read the actual release identities rather than claiming the embedded version
	// is what governed historical evaluations.
	state.ComplianceCatalogueSHA256 = stringValueFromMap(payload, "compliance_catalogue_sha256")
	state.ComplianceEvaluatorSHA256 = stringValueFromMap(payload, "compliance_evaluator_sha256")
	if value, ok := payload["compliance_revision"].(float64); ok {
		state.ComplianceRevision = types.Int64Value(int64(value))
	} else {
		state.ComplianceRevision = types.Int64Value(0)
	}
	if raw, ok := payload["compliance_coverage"]; ok && raw != nil {
		encoded, _ := json.Marshal(raw)
		var counts map[string]compliancecatalogue.Counts
		if json.Unmarshal(encoded, &counts) == nil {
			entries := map[string]attr.Value{}
			for regime, c := range counts {
				entries[regime] = types.ObjectValueMust(coverageType.AttrTypes, map[string]attr.Value{"enforced": types.Int64Value(int64(c.Enforced)), "evidence_gap": types.Int64Value(int64(c.EvidenceGap)), "not_action_time": types.Int64Value(int64(c.NotActionTime)), "total": types.Int64Value(int64(c.Total))})
			}
			state.ComplianceCoverage = types.MapValueMust(coverageType, entries)
		}
	}
	if raw, ok := payload["regimes_without_controls"]; ok && raw != nil {
		state.RegimesWithoutControls, _ = types.SetValueFrom(context.Background(), types.StringType, tfhelpers.GetStringSlice(payload, "regimes_without_controls"))
	}
}
