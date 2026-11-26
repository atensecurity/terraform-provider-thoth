package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// An exception apply whose bundle publish was held answers 202 with
// apply_pending. It must not be recorded as applied.
func TestApplyPolicyChangeArtifactReportsAHeldPublishAsPending(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"request_id":"req-1","apply_pending":true,"change_id":"c9","message":"approve it"}`))
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, TenantID: "example-tenant", AuthToken: "token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = c.ApplyPolicyChangeArtifact(context.Background(), "req-1", map[string]any{"applied_by": "x"})
	if !IsPendingApproval(err) {
		t.Fatalf("ApplyPolicyChangeArtifact() error = %v, want a pending approval", err)
	}
}

func TestApplyPolicyChangeArtifactAppliedIsNotPending(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"request_id":"req-1","artifact_id":"a1"}`))
	}))
	defer srv.Close()
	c, _ := New(Config{BaseURL: srv.URL, TenantID: "example-tenant", AuthToken: "token"})
	if _, err := c.ApplyPolicyChangeArtifact(context.Background(), "req-1", map[string]any{"applied_by": "x"}); err != nil {
		t.Fatalf("error = %v", err)
	}
}
