package resources

import (
	"fmt"
	"sort"
	"strings"
)

// Client-side copy of the gateway key rules in govapi
// (backend/go/cmd/govapi/api_key_gateway_scope.go and normalizeThothKeyKind).
// The server stays the authority; these checks only move the refusal to plan
// time. Keep the two in step: gateway_key_scope_test.go mirrors the govapi test
// rows.

const (
	gatewayKeyKind             = "mcp_gateway"
	gatewayKeyScopeMaxEntries  = 64
	gatewayKeyScopeMaxNameLen  = 128
	gatewayKeyScopeMaxEntryLen = gatewayKeyScopeMaxNameLen + len("__") + gatewayKeyScopeMaxNameLen + len("*")
	gatewayKeyToolSeparator    = "__"
	gatewayKeyScopeMinPrefix   = 3
)

// validateGatewayKeyKind checks the optional kind against the key's scope and
// permissions. An empty kind is an ordinary key.
func validateGatewayKeyKind(kind, scopeLevel string, permissions []string) error {
	switch kind {
	case "":
		return nil
	case gatewayKeyKind:
		if scopeLevel != apiKeyScopeEndpoint {
			return fmt.Errorf("an mcp_gateway key must have endpoint scope, the gateway's own endpoint: use thoth_endpoint_api_key")
		}
		if len(permissions) != 1 || permissions[0] != "execute" {
			return fmt.Errorf("an mcp_gateway key must have the execute permission only")
		}
		return nil
	default:
		return fmt.Errorf("kind must be omitted or mcp_gateway")
	}
}

// normalizeGatewayKeyScope validates the lists for the key kind and returns
// them lower-cased, de-duplicated and sorted, as the server stores them. A
// gateway key needs both lists; any other key must have neither (nil).
func normalizeGatewayKeyScope(kind string, agents, tools []string) ([]string, []string, error) {
	if kind != gatewayKeyKind {
		if agents != nil || tools != nil {
			return nil, nil, fmt.Errorf("allowed_agents and allowed_tools are accepted only with kind = \"mcp_gateway\"")
		}
		return nil, nil, nil
	}
	a, err := normalizeGatewayKeyScopeList("allowed_agents", agents, false)
	if err != nil {
		return nil, nil, err
	}
	t, err := normalizeGatewayKeyScopeList("allowed_tools", tools, true)
	if err != nil {
		return nil, nil, err
	}
	return a, t, nil
}

func normalizeGatewayKeyScopeList(field string, list []string, isTools bool) ([]string, error) {
	if len(list) == 0 {
		return nil, fmt.Errorf("an mcp_gateway key requires %s: a non-empty set", field)
	}
	if len(list) > gatewayKeyScopeMaxEntries {
		return nil, fmt.Errorf("%s may have at most %d entries", field, gatewayKeyScopeMaxEntries)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(list))
	for _, raw := range list {
		if !isTools && len(raw) > gatewayKeyScopeMaxNameLen {
			return nil, fmt.Errorf("%s entries may be at most %d characters", field, gatewayKeyScopeMaxNameLen)
		}
		if len(raw) > gatewayKeyScopeMaxEntryLen {
			return nil, fmt.Errorf("%s entries may be at most %d characters", field, gatewayKeyScopeMaxEntryLen)
		}
		if isTools {
			if err := validateGatewayKeyToolEntry(raw); err != nil {
				return nil, fmt.Errorf("%s: %w", field, err)
			}
		} else if !gatewayKeyAgentIDOK(raw) {
			return nil, fmt.Errorf("allowed_agents entries must be exact agent ids of printable ASCII characters, with no *, / or \\ and no spaces, that exist under the endpoint")
		}
		entry := strings.ToLower(raw)
		if !seen[entry] {
			seen[entry] = true
			out = append(out, entry)
		}
	}
	sort.Strings(out)
	return out, nil
}

func gatewayKeyAgentIDOK(id string) bool {
	if id == "" || len(id) > gatewayKeyScopeMaxNameLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] <= ' ' || id[i] >= 0x7f || id[i] == '*' || id[i] == '/' || id[i] == '\\' {
			return false
		}
	}
	return true
}

func gatewayKeyUpstreamOK(name string) bool {
	if name == "" || len(name) > gatewayKeyScopeMaxNameLen || strings.HasSuffix(name, "_") || strings.Contains(name, gatewayKeyToolSeparator) {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func gatewayKeyToolNameOK(tool string) bool {
	if tool == "" || tool[0] == '_' || len(tool) > gatewayKeyScopeMaxNameLen {
		return false
	}
	for i := 0; i < len(tool); i++ {
		c := tool[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

func validateGatewayKeyToolEntry(entry string) error {
	form := fmt.Errorf("allowed_tools entries must be <upstream>__<tool> or <upstream>__<tool prefix>* (at most one *, trailing, after at least %d characters), in ASCII", gatewayKeyScopeMinPrefix)
	if len(entry) > gatewayKeyScopeMaxEntryLen {
		return fmt.Errorf("entries may be at most %d characters", gatewayKeyScopeMaxEntryLen)
	}
	body, prefix := entry, false
	if strings.HasSuffix(entry, "*") {
		body, prefix = strings.TrimSuffix(entry, "*"), true
	}
	if strings.Contains(body, "*") {
		return form
	}
	upstream, tool, ok := strings.Cut(body, gatewayKeyToolSeparator)
	if !ok || !gatewayKeyUpstreamOK(upstream) {
		return form
	}
	if prefix {
		if len(body) < gatewayKeyScopeMinPrefix || (tool != "" && !gatewayKeyToolNameOK(tool)) {
			return form
		}
		return nil
	}
	if !gatewayKeyToolNameOK(tool) {
		return form
	}
	return nil
}
