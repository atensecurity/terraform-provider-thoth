package client

import (
	"context"
	"encoding/json"
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
		TenantID:  "example-tenant",
		AuthToken: "token",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := client.BackfillGovernanceEvidence(context.Background(), map[string]string{"limit": "50"}, nil)
	if err != nil {
		t.Fatalf("BackfillGovernanceEvidence() error = %v", err)
	}

	if gotPath != "/example-tenant/governance/evidence/thoth/backfill" {
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
		case "/example-tenant/governance/evidence/thoth/backfill":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(`{"error":"method_not_allowed","message":"Method Not Allowed"}`))
		case "/example-tenant/thoth/governance/evidence/thoth/backfill":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"created":3}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	client, err := New(Config{
		BaseURL:   srv.URL,
		TenantID:  "example-tenant",
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
	if gotPaths[0] != "/example-tenant/governance/evidence/thoth/backfill" {
		t.Fatalf("first path = %q", gotPaths[0])
	}
	if gotPaths[1] != "/example-tenant/thoth/governance/evidence/thoth/backfill" {
		t.Fatalf("second path = %q", gotPaths[1])
	}
	if created := resp["created"]; created != float64(3) {
		t.Fatalf("response.created = %#v", created)
	}
}

func TestListMCPVendorsIncludesApprovedQueryWhenProvided(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotApproved string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotApproved = r.URL.Query().Get("approved")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"vendor_id":"openai","display_name":"OpenAI"}]}`))
	}))
	defer srv.Close()

	c, err := New(Config{
		BaseURL:   srv.URL,
		TenantID:  "example-tenant",
		AuthToken: "token",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	approved := true
	rows, err := c.ListMCPVendors(context.Background(), &approved)
	if err != nil {
		t.Fatalf("ListMCPVendors() error = %v", err)
	}
	if gotPath != "/example-tenant/thoth/mcp/vendors" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotApproved != "true" {
		t.Fatalf("approved query = %q", gotApproved)
	}
	if len(rows) != 1 || rows[0]["vendor_id"] != "openai" {
		t.Fatalf("rows = %#v", rows)
	}
}

func TestMCPVendorCRUDEndpoints(t *testing.T) {
	t.Parallel()

	vendorID := "vendor with spaces"
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"vendor_id":"vendor with spaces","display_name":"Vendor"}`))
		case http.MethodPost:
			_, _ = w.Write([]byte(`{"vendor_id":"vendor with spaces","display_name":"Vendor"}`))
		case http.MethodPut:
			_, _ = w.Write([]byte(`{"vendor_id":"vendor with spaces","display_name":"Vendor Updated"}`))
		case http.MethodDelete:
			_, _ = w.Write([]byte(`{"deleted":true}`))
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer srv.Close()

	c, err := New(Config{
		BaseURL:   srv.URL,
		TenantID:  "example-tenant",
		AuthToken: "token",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := c.CreateMCPVendor(context.Background(), map[string]any{"vendor_id": vendorID}); err != nil {
		t.Fatalf("CreateMCPVendor() error = %v", err)
	}
	if _, err := c.GetMCPVendor(context.Background(), vendorID); err != nil {
		t.Fatalf("GetMCPVendor() error = %v", err)
	}
	if _, err := c.UpdateMCPVendor(context.Background(), vendorID, map[string]any{"display_name": "Vendor Updated"}); err != nil {
		t.Fatalf("UpdateMCPVendor() error = %v", err)
	}
	if err := c.DeleteMCPVendor(context.Background(), vendorID); err != nil {
		t.Fatalf("DeleteMCPVendor() error = %v", err)
	}

	want := []string{
		"POST /example-tenant/thoth/mcp/vendors",
		"GET /example-tenant/thoth/mcp/vendors/" + vendorID,
		"PUT /example-tenant/thoth/mcp/vendors/" + vendorID,
		"DELETE /example-tenant/thoth/mcp/vendors/" + vendorID,
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls[%d] = %q, want %q", i, calls[i], want[i])
		}
	}
}

func TestGetMCPInventoryReportUsesWindowHoursQuery(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotWindow string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotWindow = r.URL.Query().Get("window_hours")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"endpoint_id":"ep-1","unapproved_calls":2}],"total":1,"window_hours":168}`))
	}))
	defer srv.Close()

	c, err := New(Config{
		BaseURL:   srv.URL,
		TenantID:  "example-tenant",
		AuthToken: "token",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := c.GetMCPInventoryReport(context.Background(), 168)
	if err != nil {
		t.Fatalf("GetMCPInventoryReport() error = %v", err)
	}
	if gotPath != "/example-tenant/thoth/mcp/inventory/report" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotWindow != "168" {
		t.Fatalf("window_hours query = %q", gotWindow)
	}
	if total := resp["total"]; total != float64(1) {
		t.Fatalf("response.total = %#v", total)
	}
}

func TestVerifyMCPCatalogPostsPayloadAndEnv(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotEnv string
	var gotMethod string
	var gotPayload map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotEnv = r.URL.Query().Get("env")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"policy_count":3,"allowed_tools":["list_endpoints"]}`))
	}))
	defer srv.Close()

	c, err := New(Config{
		BaseURL:   srv.URL,
		TenantID:  "example-tenant",
		AuthToken: "token",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := c.VerifyMCPCatalog(context.Background(), "prod", map[string]any{
		"principal": "agent:ops",
	})
	if err != nil {
		t.Fatalf("VerifyMCPCatalog() error = %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q", gotMethod)
	}
	if gotPath != "/example-tenant/thoth/mcp/catalog/verify" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotEnv != "prod" {
		t.Fatalf("env query = %q", gotEnv)
	}
	if gotPayload["principal"] != "agent:ops" {
		t.Fatalf("payload.principal = %#v", gotPayload["principal"])
	}
	if policyCount := resp["policy_count"]; policyCount != float64(3) {
		t.Fatalf("response.policy_count = %#v", policyCount)
	}
}
