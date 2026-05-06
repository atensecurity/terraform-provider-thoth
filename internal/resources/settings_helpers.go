package resources

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

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
