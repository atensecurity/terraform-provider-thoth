package resources

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestWebhookSettingsRedactedSecretPreservesState(t *testing.T) {
	for _, prior := range []types.String{types.StringValue("configured-secret"), types.StringNull()} {
		for _, response := range []string{settingsSecretRedacted, ""} {
			state := flattenWebhookSettings(map[string]any{"webhook": map[string]any{"secret": response}}, webhookSettingsModel{WebhookSecret: prior}, "tenant-a")
			if !state.WebhookSecret.Equal(prior) {
				t.Fatal("redacted read changed webhook secret state")
			}
		}
	}
	state := flattenWebhookSettings(map[string]any{"webhook": map[string]any{"secret": "legacy-readable-secret"}}, webhookSettingsModel{}, "tenant-a")
	if state.WebhookSecret.ValueString() != "legacy-readable-secret" {
		t.Fatal("legacy server read compatibility lost")
	}
}

func TestSIEMSettingsRedactedSecretPreservesState(t *testing.T) {
	for _, prior := range []types.String{types.StringValue("configured-secret"), types.StringNull()} {
		for _, response := range []string{settingsSecretRedacted, ""} {
			state := flattenSIEMSettings(map[string]any{"siem": map[string]any{"webhook": map[string]any{"secret": response}}}, siemSettingsModel{SIEMWebhookSecret: prior}, "tenant-a")
			if !state.SIEMWebhookSecret.Equal(prior) {
				t.Fatal("redacted read changed SIEM secret state")
			}
		}
	}
}

func TestPAMSettingsRedactedSecretsPreserveState(t *testing.T) {
	for _, prior := range []types.String{types.StringValue("configured-secret"), types.StringNull()} {
		for _, response := range []string{settingsSecretRedacted, ""} {
			state := flattenPAMSettings(map[string]any{"pam": map[string]any{"callback_secret": response, "request_secret": response, "request_auth_token": response}}, pamSettingsModel{PAMCallbackSecret: prior, PAMRequestSecret: prior, PAMRequestAuthToken: prior}, "tenant-a")
			if !state.PAMCallbackSecret.Equal(prior) || !state.PAMRequestSecret.Equal(prior) || !state.PAMRequestAuthToken.Equal(prior) {
				t.Fatal("redacted read changed PAM credential state")
			}
		}
	}
}
