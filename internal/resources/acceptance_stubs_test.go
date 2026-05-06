package resources_test

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	providerpkg "github.com/atensecurity/terraform-provider-thoth/internal/provider"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"thoth": providerserver.NewProtocol6WithError(providerpkg.New("test")()),
}

func TestAccTenantSettings_basic(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run acceptance tests")
	}

	resourceName := "thoth_governance_settings.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTenantSettingsConfig("soc2"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("compliance_profile"), knownvalue.StringExact("soc2")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("shadow_medium"), knownvalue.StringExact("step_up")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				Config: testAccTenantSettingsConfig("ai_governance"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("compliance_profile"), knownvalue.StringExact("ai_governance")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"webhook_secret", "siem_webhook_secret", "pam_callback_secret", "pam_request_secret", "pam_request_auth_token"},
			},
		},
	})
}

func TestAccMDMProvider_basic(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run acceptance tests")
	}

	resourceName := "thoth_mdm_provider.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMDMProviderConfig("custom", "tf-acc-custom"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("provider_name"), knownvalue.StringExact("custom")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact("tf-acc-custom")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				Config: testAccMDMProviderConfig("custom", "tf-acc-custom-updated"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact("tf-acc-custom-updated")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"config_json"},
			},
		},
	})
}

func TestAccWebhookTest_requiresConfiguredWebhook(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run acceptance tests")
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccWebhookTestOnlyConfig(),
				ExpectError: regexp.MustCompile(`(?s)webhook_not_configured|Webhook is not enabled or URL is not set`),
			},
		},
	})
}

func testAccPreCheck(t *testing.T) {
	t.Helper()
	required := []string{
		"THOTH_TEST_TENANT_ID",
		"THOTH_TEST_ADMIN_BEARER_TOKEN",
	}
	for _, key := range required {
		if os.Getenv(key) == "" {
			t.Fatalf("%s must be set for acceptance tests", key)
		}
	}
}

func testAccProviderConfig() string {
	config := fmt.Sprintf(`
provider "thoth" {
  tenant_id          = %q
  admin_bearer_token = %q
}
`,
		os.Getenv("THOTH_TEST_TENANT_ID"),
		os.Getenv("THOTH_TEST_ADMIN_BEARER_TOKEN"),
	)

	if apiBaseURL := strings.TrimSpace(os.Getenv("THOTH_TEST_API_BASE_URL")); apiBaseURL != "" {
		config = fmt.Sprintf(`
provider "thoth" {
  api_base_url       = %q
  tenant_id          = %q
  admin_bearer_token = %q
}
`,
			apiBaseURL,
			os.Getenv("THOTH_TEST_TENANT_ID"),
			os.Getenv("THOTH_TEST_ADMIN_BEARER_TOKEN"),
		)
	}

	if apexDomain := strings.TrimSpace(os.Getenv("THOTH_TEST_APEX_DOMAIN")); apexDomain != "" {
		config = strings.TrimSuffix(config, "}\n") + fmt.Sprintf("  apex_domain        = %q\n}\n", apexDomain)
	}

	return config
}

func testAccTenantSettingsConfig(profile string) string {
	return testAccProviderConfig() + fmt.Sprintf(`
resource "thoth_governance_settings" "test" {
  compliance_profile = %q
  shadow_low         = "allow"
  shadow_medium      = "step_up"
  shadow_high        = "block"
  shadow_critical    = "block"
}
`, profile)
}

func testAccMDMProviderConfig(provider, name string) string {
	return testAccProviderConfig() + fmt.Sprintf(`
resource "thoth_mdm_provider" "test" {
  provider_name = %q
  name          = %q
  enabled       = true

  config_json = jsonencode({
    endpoint  = "https://mdm.example.com"
    api_token = "test-token"
  })
}
`, provider, name)
}

func testAccWebhookTestOnlyConfig() string {
	return testAccProviderConfig() + `
resource "thoth_webhook_test" "test" {
  trigger = "acc"
}
`
}
