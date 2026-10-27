package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writeSession(t *testing.T, dir string, session map[string]any) string {
	t.Helper()
	path := filepath.Join(dir, "tenant-a--api_example_com--admin-token.jwt")
	data, _ := json.Marshal(session)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func baseSession(expires time.Time) map[string]any {
	return map[string]any{
		"version": 1, "token": "old-token", "tenant_id": "tenant-a", "govapi_url": "https://api.example.com",
		"organization_id": "org_1", "customer_domain": "acme.example", "user_subject": "user_1",
		"expires_at_unix": expires.Unix(), "refresh_token": "refresh-1", "added_later": "kept",
	}
}

func TestLoadUserSessionChecksTheWorkspace(t *testing.T) {
	dir := t.TempDir()
	path := writeSession(t, dir, baseSession(time.Now().Add(time.Hour)))
	if _, err := LoadUserSession(path, "tenant-a", "https://api.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUserSession(path, "tenant-b", "https://api.example.com"); err == nil || !strings.Contains(err.Error(), "thothctl auth login --tenant-id tenant-b") {
		t.Fatalf("another workspace: %v", err)
	}
	if _, err := LoadUserSession(path, "tenant-a", "https://other.example.com"); err == nil {
		t.Fatal("another GovAPI must be refused")
	}
	if _, err := LoadUserSession(filepath.Join(dir, "missing"), "tenant-a", "https://api.example.com"); err == nil || !strings.Contains(err.Error(), "thothctl auth login") {
		t.Fatalf("missing: %v", err)
	}
	raw := writeSession(t, dir, map[string]any{"version": 2, "token": "x"})
	if _, err := LoadUserSession(raw, "tenant-a", "https://api.example.com"); err == nil {
		t.Fatal("an unknown session version must be refused")
	}
}

func TestDefaultSessionPathMatchesThothctl(t *testing.T) {
	t.Setenv("HOME", "/home/me")
	got, err := DefaultSessionPath("Tenant-A", "https://api.atensecurity.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/home/me/.thoth/sessions/tenant-a--api_atensecurity_com--admin-token.jwt" {
		t.Fatalf("path %s", got)
	}
}

func TestUserSessionRenewsOnceAndWritesThothctlsFile(t *testing.T) {
	var renewals atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renewals.Add(1)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["refresh_token"] != "refresh-1" || body["organization_id"] != "org_1" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-token", "refresh_token": "refresh-2", "organization_id": "org_1",
			"expires_at_unix": time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer server.Close()

	path := writeSession(t, t.TempDir(), baseSession(time.Now().Add(30*time.Second)))
	s, err := LoadUserSession(path, "tenant-a", "https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	s.renewURL = func(string, string) string { return server.URL }

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if token, err := s.Token(context.Background(), server.Client()); err != nil || token != "new-token" {
				t.Errorf("token %q, %v", token, err)
			}
		}()
	}
	wg.Wait()
	if renewals.Load() != 1 {
		t.Fatalf("renewed %d times; parallel requests share one renewal", renewals.Load())
	}

	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the session file stays private: %v %v", info.Mode(), err)
	}
	var saved map[string]any
	data, _ := os.ReadFile(path)
	_ = json.Unmarshal(data, &saved)
	if saved["token"] != "new-token" || saved["refresh_token"] != "refresh-2" || saved["added_later"] != "kept" || saved["customer_domain"] != "acme.example" {
		t.Fatalf("thothctl's file keeps every field: %v", saved)
	}
}

func TestUserSessionUsesThothctlsRenewalWhenItsOwnLoses(t *testing.T) {
	path := writeSession(t, t.TempDir(), baseSession(time.Now().Add(10*time.Second)))
	s, err := LoadUserSession(path, "tenant-a", "https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	// The refresh token was spent: thothctl renewed and saved first.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		renewed := baseSession(time.Now().Add(time.Hour))
		renewed["token"], renewed["refresh_token"] = "thothctl-token", "refresh-3"
		writeSession(t, filepath.Dir(path), renewed)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	s.renewURL = func(string, string) string { return server.URL }
	token, err := s.Token(context.Background(), server.Client())
	if err != nil || token != "thothctl-token" {
		t.Fatalf("token %q, %v", token, err)
	}
}

func TestUserSessionExpiredWithoutRefresh(t *testing.T) {
	session := baseSession(time.Now().Add(-time.Minute))
	delete(session, "refresh_token")
	path := writeSession(t, t.TempDir(), session)
	s, _ := LoadUserSession(path, "tenant-a", "https://api.example.com")
	if _, err := s.Token(context.Background(), http.DefaultClient); err == nil || !strings.Contains(err.Error(), "thothctl auth login") {
		t.Fatalf("err %v", err)
	}
}

func TestStepUpProofIsScopedAndFresh(t *testing.T) {
	home := t.TempDir()
	s := &UserSession{stored: storedSession{TenantID: "tenant-a", GovAPIURL: "https://api.example.com/"}, stepUp: filepath.Join(home, "step-up.json"), now: time.Now}
	cache := map[string]any{"proofs": map[string]any{
		"https://api.example.com/tenant-a": map[string]any{"proof": "proof-a", "expires_at_unix": time.Now().Add(10 * time.Minute).Unix()},
		"https://api.example.com/tenant-b": map[string]any{"proof": "proof-b", "expires_at_unix": time.Now().Add(10 * time.Minute).Unix()},
	}}
	data, _ := json.Marshal(cache)
	_ = os.WriteFile(s.stepUp, data, 0o600)
	if got := s.StepUpProof(); got != "proof-a" {
		t.Fatalf("proof %q", got)
	}
	s.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	if got := s.StepUpProof(); got != "" {
		t.Fatalf("an expiring proof is not sent: %q", got)
	}
}

func TestStepUpRefusalSaysHowToVerify(t *testing.T) {
	path := writeSession(t, t.TempDir(), baseSession(time.Now().Add(time.Hour)))
	s, _ := LoadUserSession(path, "tenant-a", "https://api.example.com")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer old-token" {
			t.Errorf("auth header %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"step-up authentication (MFA) required"}`))
	}))
	defer server.Close()
	c, err := New(Config{BaseURL: server.URL, TenantID: "tenant-a", Session: s})
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsSignedInUser() {
		t.Fatal("a thothctl session is a signed-in user")
	}
	_, err = c.GetTenantSettings(context.Background())
	if err == nil || !strings.Contains(err.Error(), "thothctl auth step-up --tenant-id tenant-a") {
		t.Fatalf("err %v", err)
	}
}
