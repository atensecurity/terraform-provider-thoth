package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBackfillGovernanceEvidenceUsesPrimaryPath(t *testing.T) {
	t.Parallel()

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":2}`))
	}))
	defer srv.Close()

	client, err := New(Config{
		BaseURL:   srv.URL,
		TenantID:  "delta-arc",
		AuthToken: "token",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := client.BackfillGovernanceEvidence(context.Background(), map[string]string{"limit": "50"}, nil)
	if err != nil {
		t.Fatalf("BackfillGovernanceEvidence() error = %v", err)
	}

	if gotPath != "/delta-arc/governance/evidence/thoth/backfill" {
		t.Fatalf("path = %q", gotPath)
	}
	if created := resp["created"]; created != float64(2) {
		t.Fatalf("response.created = %#v", created)
	}
}

func TestBackfillGovernanceEvidenceFallsBackOnMethodNotAllowed(t *testing.T) {
	t.Parallel()

	var gotPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		switch r.URL.Path {
		case "/delta-arc/governance/evidence/thoth/backfill":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(`{"error":"method_not_allowed","message":"Method Not Allowed"}`))
		case "/delta-arc/thoth/governance/evidence/thoth/backfill":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"created":3}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	client, err := New(Config{
		BaseURL:   srv.URL,
		TenantID:  "delta-arc",
		AuthToken: "token",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := client.BackfillGovernanceEvidence(context.Background(), map[string]string{"limit": "50"}, nil)
	if err != nil {
		t.Fatalf("BackfillGovernanceEvidence() error = %v", err)
	}

	if len(gotPaths) != 2 {
		t.Fatalf("request count = %d, want 2", len(gotPaths))
	}
	if gotPaths[0] != "/delta-arc/governance/evidence/thoth/backfill" {
		t.Fatalf("first path = %q", gotPaths[0])
	}
	if gotPaths[1] != "/delta-arc/thoth/governance/evidence/thoth/backfill" {
		t.Fatalf("second path = %q", gotPaths[1])
	}
	if created := resp["created"]; created != float64(3) {
		t.Fatalf("response.created = %#v", created)
	}
}
