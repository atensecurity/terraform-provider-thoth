package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A policy bundle change made with an API key is accepted (202) but pending: a
// signed-in org admin approves it. The provider must not treat that as applied,
// or Terraform would record a bundle that is not enforced, or forget one that is.

const heldBody = `{"change_id":"c1","status":"pending_approval","action":"publish","approval_required":true,"message":"approve it"}`

func heldClient(t *testing.T, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL, TenantID: "example-tenant", AuthToken: "token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return c
}

func TestCreatePolicyBundleReportsAHeldChangeAsPending(t *testing.T) {
	t.Parallel()
	_, err := heldClient(t, heldBody).CreatePolicyBundle(context.Background(), map[string]any{"name": "x"}, nil)
	if !IsPendingApproval(err) {
		t.Fatalf("CreatePolicyBundle() error = %v, want a pending approval", err)
	}
	if !strings.Contains(err.Error(), "c1") {
		t.Fatalf("the error names the change id: %v", err)
	}
}

func TestDeletePolicyBundleReportsAHeldChangeAsPending(t *testing.T) {
	t.Parallel()
	err := heldClient(t, strings.Replace(heldBody, "publish", "delete", 1)).DeletePolicyBundle(context.Background(), "b1")
	if !IsPendingApproval(err) {
		t.Fatalf("DeletePolicyBundle() error = %v, want a pending approval: a held delete is not a delete", err)
	}
}

func TestAppliedPolicyBundleChangesAreNotPending(t *testing.T) {
	t.Parallel()
	out, err := heldClient(t, `{"id":"b1","name":"x"}`).CreatePolicyBundle(context.Background(), map[string]any{"name": "x"}, nil)
	if err != nil || out["id"] != "b1" {
		t.Fatalf("CreatePolicyBundle() = %v, %v", out, err)
	}
	if err := heldClient(t, `{"status":"deleted"}`).DeletePolicyBundle(context.Background(), "b1"); err != nil {
		t.Fatalf("DeletePolicyBundle() error = %v", err)
	}
}
