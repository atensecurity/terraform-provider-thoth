package resources

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/compliancecatalogue"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func complianceModel(values ...string) governanceSettingsModel {
	set, _ := types.SetValueFrom(context.Background(), types.StringType, values)
	return governanceSettingsModel{DeclaredRegulatoryRegimes: set, ComplianceEnforcementMode: types.StringValue("observe")}
}
func TestComplianceValidation(t *testing.T) {
	for _, regime := range compliancecatalogue.Manifest().Regimes {
		for _, value := range []string{regime.Slug, regime.Canonical, strings.ToUpper(strings.ReplaceAll(regime.Slug, "_", " / "))} {
			var diags diag.Diagnostics
			validateComplianceConfig(context.Background(), complianceModel(value), &diags)
			if diags.HasError() {
				t.Fatalf("%s: %v", value, diags)
			}
		}
	}
	cases := []struct {
		name  string
		model governanceSettingsModel
		error bool
	}{
		{"invalid", complianceModel("nonsense"), true},
		{"legal conflation", complianceModel("hipaa-hitech"), true},
		{"duplicate", complianceModel("SOC 2", "soc2"), true},
		{"missing mode", governanceSettingsModel{DeclaredRegulatoryRegimes: complianceModel("soc2").DeclaredRegulatoryRegimes}, true},
		{"mode alone", governanceSettingsModel{ComplianceEnforcementMode: types.StringValue("enforce")}, true},
		{"unknown", governanceSettingsModel{DeclaredRegulatoryRegimes: types.SetUnknown(types.StringType), ComplianceEnforcementMode: types.StringUnknown()}, false},
		{"unknown element", governanceSettingsModel{DeclaredRegulatoryRegimes: types.SetValueMust(types.StringType, []attr.Value{types.StringUnknown()}), ComplianceEnforcementMode: types.StringUnknown()}, false},
		{"unknown plus invalid", governanceSettingsModel{DeclaredRegulatoryRegimes: types.SetValueMust(types.StringType, []attr.Value{types.StringUnknown(), types.StringValue("bogus")}), ComplianceEnforcementMode: types.StringUnknown()}, true},
		{"null element", governanceSettingsModel{DeclaredRegulatoryRegimes: types.SetValueMust(types.StringType, []attr.Value{types.StringNull()}), ComplianceEnforcementMode: types.StringValue("observe")}, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var d diag.Diagnostics
			validateComplianceConfig(context.Background(), tt.model, &d)
			if d.HasError() != tt.error {
				t.Fatalf("%v", d)
			}
		})
	}
	for _, key := range []string{"DECLARED_REGULATORY_REGIMES", "declared_regulatory_regimes", "compliance_enforcement_mode", "compliance_expected_revision", "compliance_request_id", "compliance_catalogue_sha256", "compliance", "regimes_without_controls"} {
		model := complianceModel("soc2")
		model.ExtraSettingsJSON = types.StringValue(`{"` + key + `":null}`)
		var d diag.Diagnostics
		validateComplianceConfig(context.Background(), model, &d)
		if !d.HasError() {
			t.Fatalf("accepted reserved key %s", key)
		}
	}
}
func TestComplianceFirstPlanKnownCoverage(t *testing.T) {
	ctx := context.Background()
	r := &governanceSettingsResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	attrTypes := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object).AttributeTypes
	fields := map[string]tftypes.Value{}
	for key, typ := range attrTypes {
		fields[key] = tftypes.NewValue(typ, nil)
	}
	fields["declared_regulatory_regimes"] = tftypes.NewValue(attrTypes["declared_regulatory_regimes"], []tftypes.Value{tftypes.NewValue(tftypes.String, "fedramp"), tftypes.NewValue(tftypes.String, "cmmc_l1"), tftypes.NewValue(tftypes.String, "iso_27001")})
	fields["compliance_enforcement_mode"] = tftypes.NewValue(tftypes.String, "observe")
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), fields)}
	req := resource.ModifyPlanRequest{Plan: plan, State: tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)}}
	resp := resource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(ctx, req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	var got governanceSettingsModel
	if d := resp.Plan.Get(ctx, &got); d.HasError() {
		t.Fatal(d)
	}
	if got.ComplianceCoverage.IsUnknown() || len(got.ComplianceCoverage.Elements()) != 3 {
		t.Fatal(got.ComplianceCoverage)
	}
	if got.RegimesWithoutControls.String() != `["ISO 27001"]` {
		t.Fatal(got.RegimesWithoutControls)
	}
	if got.ComplianceCoverage.Elements()["ISO 27001"].(types.Object).Attributes()["enforced"].(types.Int64).ValueInt64() != 0 {
		t.Fatal("unserved incorrectly has executable controls")
	}
	if got.PropagationMaxMS.ValueInt64() != 1000 {
		t.Fatal(got.PropagationMaxMS)
	}
}
func complianceServer(t *testing.T, capabilityChange func(map[string]any), updateStatus int) (*governanceSettingsResource, *[]map[string]any) {
	t.Helper()
	writes := []map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.URL.Path == "/test/thoth/compliance/catalogue" {
			b, _ := json.Marshal(compliancecatalogue.Manifest())
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			m["transactional_declarations_supported"] = true
			if capabilityChange != nil {
				capabilityChange(m)
			}
			_ = json.NewEncoder(w).Encode(m)
			return
		}
		if req.URL.Path != "/test/thoth/settings" {
			t.Errorf("path %s", req.URL.Path)
			w.WriteHeader(404)
			return
		}
		if req.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"compliance_profile": "soc2", "declared_regulatory_regimes": []string{"HIPAA"}, "compliance_enforcement_mode": "enforce", "compliance_revision": 42, "compliance_request_id": "read-only-id"})
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		writes = append(writes, maps.Clone(payload))
		if updateStatus != 0 {
			w.WriteHeader(updateStatus)
			_, _ = w.Write([]byte(`{"error":"compliance_revision_conflict"}`))
			return
		}
		payload["compliance_revision"] = payload["compliance_expected_revision"].(float64) + 1
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "test", APIKey: "fixture", RetryMaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	return &governanceSettingsResource{client: c, tenantID: "test"}, &writes
}
func TestComplianceMutationPreconditions(t *testing.T) {
	for _, key := range []string{"catalogue_sha256", "evaluator_sha256", "transactional_declarations_supported"} {
		t.Run(key, func(t *testing.T) {
			r, writes := complianceServer(t, func(m map[string]any) { delete(m, key) }, 0)
			var d diag.Diagnostics
			_, ok := r.apply(context.Background(), complianceModel("soc2"), governanceSettingsModel{}, &d)
			if ok || !d.HasError() || len(*writes) != 0 {
				t.Fatalf("mutation before preflight: %v %v", *writes, d)
			}
		})
	}
	r, writes := complianceServer(t, nil, 0)
	prior := complianceModel("hipaa")
	prior.ComplianceRevision = types.Int64Value(7)
	var d diag.Diagnostics
	next, ok := r.apply(context.Background(), complianceModel("SOC_2"), prior, &d)
	if !ok {
		t.Fatal(d)
	}
	payload := (*writes)[0]
	if payload["compliance_expected_revision"] != float64(7) {
		t.Fatalf("must use prior revision, not freshly read 42: %v", payload)
	}
	if payload["compliance_request_id"] == "read-only-id" || len(payload["compliance_request_id"].(string)) > 128 {
		t.Fatal(payload)
	}
	if next.DeclaredRegulatoryRegimes.String() != `["SOC_2"]` {
		t.Fatal("aliases were rewritten", next.DeclaredRegulatoryRegimes)
	}
	payload2 := map[string]any{}
	if !r.applyComplianceMutation(context.Background(), payload2, complianceModel("SOC_2"), prior, &d) {
		t.Fatal(d)
	}
	if payload2["compliance_request_id"] != payload["compliance_request_id"] {
		t.Fatal("retry identity changed")
	}
}
func TestComplianceRemovalAndConflict(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "omitted", true: "empty"}[empty], func(t *testing.T) {
			r, writes := complianceServer(t, nil, 0)
			prior := complianceModel("soc2")
			prior.ComplianceRevision = types.Int64Value(9)
			plan := governanceSettingsModel{}
			if empty {
				plan.DeclaredRegulatoryRegimes = types.SetValueMust(types.StringType, []attr.Value{})
			}
			var d diag.Diagnostics
			_, ok := r.apply(context.Background(), plan, prior, &d)
			if !ok {
				t.Fatal(d)
			}
			p := (*writes)[0]
			if len(p["declared_regulatory_regimes"].([]any)) != 0 || p["compliance_enforcement_mode"] != nil || p["compliance_expected_revision"] != float64(9) {
				t.Fatal(p)
			}
		})
	}
	r, writes := complianceServer(t, nil, http.StatusConflict)
	prior := complianceModel("soc2")
	prior.ComplianceRevision = types.Int64Value(9)
	var d diag.Diagnostics
	_, ok := r.apply(context.Background(), complianceModel("hipaa"), prior, &d)
	if ok || !d.HasError() || len(*writes) != 1 {
		t.Fatalf("%v %v", *writes, d)
	}
}
func TestComplianceLegacyPayloadDoesNotEchoDeclaration(t *testing.T) {
	r, _ := complianceServer(t, nil, 0)
	payload := map[string]any{"declared_regulatory_regimes": []string{"soc2"}, "compliance_enforcement_mode": "enforce", "compliance_revision": int64(3), "regimes_without_controls": []string{}, "compliance_profile": "soc2"}
	stripComplianceFields(payload)
	var d diag.Diagnostics
	if !r.applyComplianceMutation(context.Background(), payload, governanceSettingsModel{}, governanceSettingsModel{}, &d) {
		t.Fatal(d)
	}
	if len(payload) != 1 || payload["compliance_profile"] != "soc2" {
		t.Fatal(payload)
	}
}

func complianceTerraformState(t *testing.T, managed bool, revision int64) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	r := &governanceSettingsResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	object := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	fields := map[string]tftypes.Value{}
	for key, typ := range object.AttributeTypes {
		fields[key] = tftypes.NewValue(typ, nil)
	}
	fields["compliance_revision"] = tftypes.NewValue(tftypes.Number, revision)
	if managed {
		fields["declared_regulatory_regimes"] = tftypes.NewValue(object.AttributeTypes["declared_regulatory_regimes"], []tftypes.Value{tftypes.NewValue(tftypes.String, "soc2")})
		fields["compliance_enforcement_mode"] = tftypes.NewValue(tftypes.String, "observe")
	}
	return tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(object, fields)}
}
func TestComplianceDestroyOnlyManagedFields(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "managed"}[managed], func(t *testing.T) {
			r, writes := complianceServer(t, nil, 0)
			var resp resource.DeleteResponse
			r.Delete(context.Background(), resource.DeleteRequest{State: complianceTerraformState(t, managed, 11)}, &resp)
			if resp.Diagnostics.HasError() {
				t.Fatal(resp.Diagnostics)
			}
			if !managed {
				if len(*writes) != 0 {
					t.Fatal("legacy destroy mutated settings")
				}
				return
			}
			if len(*writes) != 1 {
				t.Fatal(*writes)
			}
			payload := (*writes)[0]
			if len(payload) != 6 || payload["compliance_expected_revision"] != float64(11) || payload["compliance_enforcement_mode"] != nil || len(payload["declared_regulatory_regimes"].([]any)) != 0 {
				t.Fatal(payload)
			}
		})
	}
	r, writes := complianceServer(t, nil, http.StatusConflict)
	var resp resource.DeleteResponse
	r.Delete(context.Background(), resource.DeleteRequest{State: complianceTerraformState(t, true, 10)}, &resp)
	if !resp.Diagnostics.HasError() || len(*writes) != 1 {
		t.Fatal("stale destroy must report conflict", resp.Diagnostics)
	}
}
func TestComplianceReadPreservesOwnershipAndUnmanagedDefaults(t *testing.T) {
	payload := map[string]any{"declared_regulatory_regimes": []any{"HIPAA"}, "compliance_enforcement_mode": "enforce", "compliance_revision": float64(5), "compliance_profile": "soc2", "regulatory_regimes": []string{"soc2"}}
	prior := governanceSettingsModel{DeclaredRegulatoryRegimes: types.SetNull(types.StringType)}
	got := flattenGovernanceSettings(payload, prior, "test")
	if !got.DeclaredRegulatoryRegimes.IsNull() || !got.ComplianceEnforcementMode.IsNull() {
		t.Fatal("read adopted an unmanaged declaration")
	}
	if !got.ComplianceProfile.IsNull() || !got.RegulatoryRegimes.IsNull() || !got.SecretBrokerEnabled.IsNull() {
		t.Fatal("API defaults changed optional null fields")
	}
	got = flattenGovernanceSettings(payload, complianceModel("hipaa"), "test")
	if got.DeclaredRegulatoryRegimes.String() != `["hipaa"]` || got.ComplianceEnforcementMode.ValueString() != "enforce" || got.ComplianceRevision.ValueInt64() != 5 {
		t.Fatal(got)
	}
}
