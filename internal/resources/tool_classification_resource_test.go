package resources

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestToolClassificationContextIsSentOnlyWhenSetAndClearedWhenRemoved(t *testing.T) {
	set := toolClassificationModel{TargetSensitivity: types.StringValue("restricted"), ActingPrivilege: types.StringNull()}
	body := map[string]any{}
	contextFields(body, &set, nil)
	if body["target_sensitivity"] != "restricted" {
		t.Fatalf("a set value is sent: %v", body)
	}
	if _, present := body["acting_privilege"]; present {
		t.Fatalf("an unset value is left out, so older APIs keep accepting the write: %v", body)
	}

	unused := toolClassificationModel{TargetSensitivity: types.StringNull(), ActingPrivilege: types.StringNull()}
	body = map[string]any{}
	contextFields(body, &unused, &unused)
	if len(body) != 0 {
		t.Fatalf("configurations without the fields send nothing new: %v", body)
	}

	prior := toolClassificationModel{TargetSensitivity: types.StringValue("restricted"), ActingPrivilege: types.StringValue("admin")}
	removed := toolClassificationModel{TargetSensitivity: types.StringValue("restricted"), ActingPrivilege: types.StringNull()}
	body = map[string]any{}
	contextFields(body, &removed, &prior)
	if body["acting_privilege"] != "" || body["target_sensitivity"] != "restricted" {
		t.Fatalf("a value removed from configuration is cleared: %v", body)
	}
}
