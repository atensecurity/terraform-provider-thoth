package tfhelpers

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/meta"
)

func RequireResourceClient(req resource.ConfigureRequest, resp *resource.ConfigureResponse) *meta.ClientData {
	if req.ProviderData == nil {
		return nil
	}
	data, ok := req.ProviderData.(*meta.ClientData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Provider Data Type",
			"Expected provider metadata to be *meta.ClientData.",
		)
		return nil
	}
	return data
}

func RequireDataSourceClient(req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) *meta.ClientData {
	if req.ProviderData == nil {
		return nil
	}
	data, ok := req.ProviderData.(*meta.ClientData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Provider Data Type",
			"Expected provider metadata to be *meta.ClientData.",
		)
		return nil
	}
	return data
}

func ParseJSONObject(raw string) (map[string]any, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(trimmed), &out); err != nil {
		return nil, err
	}
	if out == nil {
		return map[string]any{}, nil
	}
	return out, nil
}

func ParseJSONArray(raw string) ([]map[string]any, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return []map[string]any{}, nil
	}
	var out []map[string]any
	if err := json.Unmarshal([]byte(trimmed), &out); err != nil {
		return nil, err
	}
	if out == nil {
		return []map[string]any{}, nil
	}
	return out, nil
}

func ToJSONString(v any) string {
	if v == nil {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func ToJSONArrayString(v any) string {
	if v == nil {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func GetMap(m map[string]any, key string) map[string]any {
	if raw, ok := m[key].(map[string]any); ok {
		return raw
	}
	return map[string]any{}
}

func GetString(m map[string]any, key string) string {
	raw, ok := m[key]
	if !ok || raw == nil {
		return ""
	}
	switch typed := raw.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func GetBool(m map[string]any, key string) bool {
	raw, ok := m[key]
	if !ok || raw == nil {
		return false
	}
	switch typed := raw.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	case float64:
		return typed != 0
	case int:
		return typed != 0
	default:
		return false
	}
}

func GetInt64(m map[string]any, key string) int64 {
	raw, ok := m[key]
	if !ok || raw == nil {
		return 0
	}
	switch typed := raw.(type) {
	case int:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	case json.Number:
		v, _ := typed.Int64()
		return v
	case string:
		v, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return v
	default:
		return 0
	}
}

func GetFloat64(m map[string]any, key string) float64 {
	raw, ok := m[key]
	if !ok || raw == nil {
		return 0
	}
	switch typed := raw.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case string:
		v, _ := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return v
	default:
		return 0
	}
}

func GetStringSlice(m map[string]any, key string) []string {
	raw, ok := m[key]
	if !ok || raw == nil {
		return []string{}
	}
	arr, ok := raw.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if item == nil {
			continue
		}
		out = append(out, fmt.Sprintf("%v", item))
	}
	return out
}

func GetStringMap(m map[string]any, key string) map[string]string {
	raw, ok := m[key]
	if !ok || raw == nil {
		return map[string]string{}
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return map[string]string{}
	}
	out := make(map[string]string, len(obj))
	for k, v := range obj {
		out[k] = fmt.Sprintf("%v", v)
	}
	return out
}

func FindByStringField(rows []map[string]any, field, value string) (map[string]any, bool) {
	needle := strings.TrimSpace(value)
	for _, row := range rows {
		if strings.TrimSpace(GetString(row, field)) == needle {
			return row, true
		}
	}
	return nil, false
}

func StringSliceValue(values []string) types.List {
	items := make([]types.String, 0, len(values))
	for _, v := range values {
		items = append(items, types.StringValue(v))
	}
	list, _ := types.ListValueFrom(nil, types.StringType, items)
	return list
}

func StringMapValue(values map[string]string) types.Map {
	if values == nil {
		values = map[string]string{}
	}
	mapValue, _ := types.MapValueFrom(nil, types.StringType, values)
	return mapValue
}

func SortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
