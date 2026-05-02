package data_sources

import (
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

func nullableString(m map[string]any, key string) types.String {
	v := strings.TrimSpace(tfhelpers.GetString(m, key))
	if v == "" {
		return types.StringNull()
	}
	return types.StringValue(v)
}
