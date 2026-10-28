package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Policy rules: GovAPI's /thoth/policies routes. A rule lives in one
// environment (dev or prod), and every call names it.

// ListPolicies lists the tenant's rules in one environment.
func (c *Client) ListPolicies(ctx context.Context, environment string) ([]map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("policies"), map[string]string{"env": environment}, nil, &out, true)
	if err != nil {
		return nil, err
	}
	rows, _ := out["policies"].([]any)
	policies := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if policy, ok := row.(map[string]any); ok {
			policies = append(policies, policy)
		}
	}
	return policies, nil
}

// GetPolicy reads one rule. GovAPI has no single-rule read, so it lists the
// environment and returns a not-found APIError when the rule is gone.
func (c *Client) GetPolicy(ctx context.Context, policyID, environment string) (map[string]any, error) {
	policies, err := c.ListPolicies(ctx, environment)
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		if id, _ := policy["id"].(string); id == strings.TrimSpace(policyID) {
			return policy, nil
		}
	}
	return nil, &APIError{StatusCode: http.StatusNotFound, Code: "not_found", Message: "Policy not found"}
}

func (c *Client) CreatePolicy(ctx context.Context, environment string, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("policies"), map[string]string{"env": environment}, payload, &out, false)
	return out, err
}

func (c *Client) UpdatePolicy(ctx context.Context, policyID, environment string, payload map[string]any) error {
	path := c.tenantPath(fmt.Sprintf("policies/%s", strings.TrimSpace(policyID)))
	return c.doJSON(ctx, http.MethodPut, path, map[string]string{"env": environment}, payload, nil, false)
}

func (c *Client) DeletePolicy(ctx context.Context, policyID, environment string) error {
	path := c.tenantPath(fmt.Sprintf("policies/%s", strings.TrimSpace(policyID)))
	return c.doJSON(ctx, http.MethodDelete, path, map[string]string{"env": environment}, nil, nil, false)
}
