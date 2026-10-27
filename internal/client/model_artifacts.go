package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Model artifact registry (GovAPI thoth_model_artifacts.go). An artifact is
// registered once and then moves through provenance verification, screening
// or a waiver, and activation. GovAPI has no update or delete route: the
// record and its activation evidence are kept.

func (c *Client) modelArtifactPath(artifactID, action string) (string, error) {
	id := strings.TrimSpace(artifactID)
	if id == "" {
		return "", errors.New("artifact_id must be non-empty")
	}
	path := "model-artifacts/" + url.PathEscape(id)
	if action != "" {
		path += "/" + action
	}
	return c.tenantPath(path), nil
}

func (c *Client) ListModelArtifacts(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("model-artifacts"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetModelArtifact(ctx context.Context, artifactID string) (map[string]any, error) {
	path, err := c.modelArtifactPath(artifactID, "")
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	err = c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) CreateModelArtifact(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("model-artifacts"), nil, payload, &out, false)
	return out, err
}

// modelArtifactAction posts one lifecycle step. These are not retried: a
// screening or activation is recorded as evidence each time it runs.
func (c *Client) modelArtifactAction(ctx context.Context, artifactID, action string, payload map[string]any) (map[string]any, error) {
	path, err := c.modelArtifactPath(artifactID, action)
	if err != nil {
		return nil, err
	}
	if payload == nil {
		payload = map[string]any{}
	}
	out := map[string]any{}
	if err := c.doJSON(ctx, http.MethodPost, path, nil, payload, &out, false); err != nil {
		return nil, fmt.Errorf("%s: %w", action, err)
	}
	return out, nil
}

func (c *Client) VerifyModelArtifactProvenance(ctx context.Context, artifactID string, payload map[string]any) (map[string]any, error) {
	return c.modelArtifactAction(ctx, artifactID, "provenance/verify", payload)
}

func (c *Client) ScreenModelArtifact(ctx context.Context, artifactID string, payload map[string]any) (map[string]any, error) {
	return c.modelArtifactAction(ctx, artifactID, "screen", payload)
}

func (c *Client) WaiveModelArtifact(ctx context.Context, artifactID, reason string) (map[string]any, error) {
	return c.modelArtifactAction(ctx, artifactID, "waive", map[string]any{"reason": reason})
}

func (c *Client) ActivateModelArtifact(ctx context.Context, artifactID string) (map[string]any, error) {
	return c.modelArtifactAction(ctx, artifactID, "activate", nil)
}
