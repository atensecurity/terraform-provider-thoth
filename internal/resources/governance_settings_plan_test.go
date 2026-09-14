package resources

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func routerPlanState() governanceSettingsModel {
	return governanceSettingsModel{
		ModelRouterEnabled:           types.BoolValue(true),
		ModelRouterDefaultProvider:   types.StringValue("openai"),
		ModelRouterDefaultModel:      types.StringValue("fixture-model"),
		ModelRouterAllowedProviders:  types.ListValueMust(types.StringType, []attr.Value{types.StringValue("openai")}),
		ModelRouterAllowedModels:     types.ListValueMust(types.StringType, []attr.Value{types.StringValue("fixture-model")}),
		ModelRouterFailoverProviders: types.ListValueMust(types.StringType, []attr.Value{types.StringValue("anthropic")}),
		SecretBrokerProvider:         types.StringValue("custom"),
	}
}

func unknownRouterPlan() governanceSettingsModel {
	return governanceSettingsModel{
		ModelRouterEnabled: types.BoolUnknown(), ModelRouterDefaultProvider: types.StringUnknown(),
		ModelRouterDefaultModel: types.StringUnknown(), ModelRouterAllowedProviders: types.ListUnknown(types.StringType),
		ModelRouterAllowedModels: types.ListUnknown(types.StringType), ModelRouterFailoverProviders: types.ListUnknown(types.StringType),
		SecretBrokerProvider: types.StringUnknown(),
	}
}

func TestGovernanceComputedPlanUnchangedInputs(t *testing.T) {
	for _, configured := range []bool{false, true} {
		prior := routerPlanState()
		config := governanceSettingsModel{}
		if configured {
			config = prior
		}
		prior.ExtraSettingsJSON = types.StringValue(`{"unrelated_flag":true}`)
		config.ExtraSettingsJSON = prior.ExtraSettingsJSON
		plan := unknownRouterPlan()
		stabilizeGovernanceComputedPlan(&plan, config, prior)
		if !plan.ModelRouterEnabled.Equal(prior.ModelRouterEnabled) ||
			!plan.ModelRouterDefaultProvider.Equal(prior.ModelRouterDefaultProvider) ||
			!plan.ModelRouterDefaultModel.Equal(prior.ModelRouterDefaultModel) ||
			!plan.ModelRouterAllowedProviders.Equal(prior.ModelRouterAllowedProviders) ||
			!plan.ModelRouterAllowedModels.Equal(prior.ModelRouterAllowedModels) ||
			!plan.ModelRouterFailoverProviders.Equal(prior.ModelRouterFailoverProviders) ||
			!plan.SecretBrokerProvider.Equal(prior.SecretBrokerProvider) {
			t.Fatalf("unchanged routing inputs did not preserve computed values: %+v", plan)
		}
	}
}

func TestGovernanceComputedPlanChangedRouterInputs(t *testing.T) {
	cases := map[string]func(*governanceSettingsModel){
		"enabled":  func(m *governanceSettingsModel) { m.ModelRouterEnabled = types.BoolValue(false) },
		"provider": func(m *governanceSettingsModel) { m.ModelRouterDefaultProvider = types.StringValue("anthropic") },
		"model":    func(m *governanceSettingsModel) { m.ModelRouterDefaultModel = types.StringValue("next-model") },
		"allowed providers": func(m *governanceSettingsModel) {
			m.ModelRouterAllowedProviders = types.ListValueMust(types.StringType, []attr.Value{})
		},
		"allowed models": func(m *governanceSettingsModel) {
			m.ModelRouterAllowedModels = types.ListValueMust(types.StringType, []attr.Value{})
		},
		"failover": func(m *governanceSettingsModel) {
			m.ModelRouterFailoverProviders = types.ListValueMust(types.StringType, []attr.Value{})
		},
		"unknown bool":   func(m *governanceSettingsModel) { m.ModelRouterEnabled = types.BoolUnknown() },
		"unknown string": func(m *governanceSettingsModel) { m.ModelRouterDefaultModel = types.StringUnknown() },
		"unknown list":   func(m *governanceSettingsModel) { m.ModelRouterAllowedModels = types.ListUnknown(types.StringType) },
		"unknown element": func(m *governanceSettingsModel) {
			m.ModelRouterAllowedModels = types.ListValueMust(types.StringType, []attr.Value{types.StringUnknown()})
		},
		"extra changed": func(m *governanceSettingsModel) {
			m.ExtraSettingsJSON = types.StringValue(`{"model_router":{"enabled":false}}`)
		},
		"extra unknown": func(m *governanceSettingsModel) { m.ExtraSettingsJSON = types.StringUnknown() },
	}
	for name, configure := range cases {
		t.Run(name, func(t *testing.T) {
			prior, config, plan := routerPlanState(), governanceSettingsModel{}, unknownRouterPlan()
			configure(&config)
			stabilizeGovernanceComputedPlan(&plan, config, prior)
			if !plan.ModelRouterEnabled.IsUnknown() || !plan.ModelRouterDefaultProvider.IsUnknown() ||
				!plan.ModelRouterDefaultModel.IsUnknown() || !plan.ModelRouterAllowedProviders.IsUnknown() ||
				!plan.ModelRouterAllowedModels.IsUnknown() || !plan.ModelRouterFailoverProviders.IsUnknown() {
				t.Fatalf("changed or unresolved input froze computed routing values: %+v", plan)
			}
		})
	}
}

func TestGovernanceComputedPlanBrokerInputs(t *testing.T) {
	for _, change := range []string{"enable", "provider", "extra", "unknown"} {
		t.Run(change, func(t *testing.T) {
			prior, config, plan := routerPlanState(), governanceSettingsModel{}, unknownRouterPlan()
			switch change {
			case "enable":
				config.SecretBrokerEnabled = types.BoolValue(true)
			case "provider":
				config.SecretBrokerProvider = types.StringValue("vault")
			case "extra":
				config.ExtraSettingsJSON = types.StringValue(`{"secret_broker":{"provider":"vault"}}`)
			case "unknown":
				config.SecretBrokerProvider = types.StringUnknown()
			}
			stabilizeGovernanceComputedPlan(&plan, config, prior)
			if !plan.SecretBrokerProvider.IsUnknown() {
				t.Fatal("changed broker inputs froze provider")
			}
		})
	}
}

func TestGovernanceRouterPayloadUsesChangedConfiguration(t *testing.T) {
	for _, extra := range []bool{false, true} {
		prior := routerPlanState()
		config := governanceSettingsModel{ModelRouterDefaultModel: types.StringValue("next-model")}
		if extra {
			config = governanceSettingsModel{ExtraSettingsJSON: types.StringValue(`{"model_router":{"default_model":"next-model"}}`)}
		}
		plan := unknownRouterPlan()
		plan.ExtraSettingsJSON = config.ExtraSettingsJSON
		plan.ModelRouterDefaultModel = config.ModelRouterDefaultModel
		if extra {
			plan.ModelRouterDefaultModel = types.StringUnknown()
		}
		stabilizeGovernanceComputedPlan(&plan, config, prior)
		payload := map[string]any{"model_router": map[string]any{"default_model": "fixture-model"}}
		var d diag.Diagnostics
		applyGovernanceSettingsPlan(&payload, plan, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if payload["model_router"].(map[string]any)["default_model"] != "next-model" {
			t.Fatal(payload)
		}
	}
}

func TestGovernanceComputedPlanExtraJSONCanReassertRefreshedDrift(t *testing.T) {
	prior, config, plan := routerPlanState(), governanceSettingsModel{}, unknownRouterPlan()
	prior.ExtraSettingsJSON = types.StringValue(`{"model_router":{"default_model":"next-model"},"secret_broker":{"provider":"vault"}}`)
	config.ExtraSettingsJSON = prior.ExtraSettingsJSON
	stabilizeGovernanceComputedPlan(&plan, config, prior)
	if !plan.ModelRouterDefaultModel.IsUnknown() || !plan.SecretBrokerProvider.IsUnknown() {
		t.Fatal("unchanged extra JSON froze refreshed values that apply will overwrite")
	}
}
