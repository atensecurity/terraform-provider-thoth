package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A signed-in user's session, saved by `thothctl auth login`.
//
// Some changes belong to a person, not a machine: appointing Slack reviewers
// and managing team members need a verified WorkOS user. The provider reuses
// the session thothctl saved (as cloud providers reuse their CLI's login),
// because a Terraform run cannot show a sign-in prompt. The file format,
// renewal and step-up cache match thothctl (backend/rust/crates/thoth,
// helpers.rs), so the provider and thothctl can share one login.

const (
	storedSessionVersion   = 1
	sessionRenewMargin     = 60 * time.Second
	stepUpProofHeader      = "X-Aten-Step-Up-Proof"
	stepUpProofMinValidity = 30 * time.Second
)

// storedSession is thothctl's StoredAuthSession. Unknown fields are kept so
// writing the renewed session back loses nothing thothctl saved.
type storedSession struct {
	Version        int    `json:"version"`
	Token          string `json:"token"`
	TenantID       string `json:"tenant_id"`
	GovAPIURL      string `json:"govapi_url"`
	OrganizationID string `json:"organization_id"`
	CustomerDomain string `json:"customer_domain"`
	UserSubject    string `json:"user_subject"`
	ExpiresAtUnix  int64  `json:"expires_at_unix"`
	RefreshToken   string `json:"refresh_token,omitempty"`
	extra          map[string]json.RawMessage
}

func (s *storedSession) UnmarshalJSON(data []byte) error {
	type plain storedSession
	if err := json.Unmarshal(data, (*plain)(s)); err != nil {
		return err
	}
	return json.Unmarshal(data, &s.extra)
}

func (s storedSession) MarshalJSON() ([]byte, error) {
	type plain storedSession
	known, err := json.Marshal(plain(s))
	if err != nil {
		return nil, err
	}
	merged := map[string]json.RawMessage{}
	for key, value := range s.extra {
		merged[key] = value
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(known, &fields); err != nil {
		return nil, err
	}
	for key, value := range fields {
		merged[key] = value
	}
	if s.RefreshToken == "" {
		delete(merged, "refresh_token")
	}
	return json.MarshalIndent(merged, "", "  ")
}

// UserSession supplies a signed-in user's token, renewing it when needed.
type UserSession struct {
	mu       sync.Mutex
	path     string
	stored   storedSession
	stepUp   string // ~/.thoth/step-up.json
	now      func() time.Time
	renewURL func(base, tenant string) string
}

// DefaultSessionPath is where `thothctl auth login` saves the session for
// a tenant and GovAPI URL: ~/.thoth/sessions/<tenant>--<host>--admin-token.jwt.
func DefaultSessionPath(tenantID, govapiURL string) (string, error) {
	parsed, err := url.Parse(govapiURL)
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("GovAPI URL %q has no host", govapiURL)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find the home directory for the thothctl session: %w", err)
	}
	host := strings.ReplaceAll(strings.ToLower(parsed.Hostname()), ".", "_")
	name := strings.ToLower(strings.TrimSpace(tenantID)) + "--" + host + "--admin-token.jwt"
	return filepath.Join(home, ".thoth", "sessions", name), nil
}

// LoadUserSession reads a thothctl session and checks it belongs to this
// tenant and GovAPI.
func LoadUserSession(path, tenantID, govapiURL string) (*UserSession, error) {
	s := &UserSession{path: path, now: time.Now}
	if home, err := os.UserHomeDir(); err == nil {
		s.stepUp = filepath.Join(home, ".thoth", "step-up.json")
	}
	if err := s.reload(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(s.stored.TenantID, strings.TrimSpace(tenantID)) {
		return nil, fmt.Errorf("the thothctl session in %s is for workspace %q, not %q; run `thothctl auth login --tenant-id %s`", path, s.stored.TenantID, tenantID, tenantID)
	}
	if strings.TrimRight(s.stored.GovAPIURL, "/") != strings.TrimRight(govapiURL, "/") {
		return nil, fmt.Errorf("the thothctl session in %s is for %s, not %s", path, s.stored.GovAPIURL, govapiURL)
	}
	return s, nil
}

func (s *UserSession) reload() error {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no thothctl session at %s; run `thothctl auth login` first", s.path)
	}
	if err != nil {
		return fmt.Errorf("read the thothctl session: %w", err)
	}
	var stored storedSession
	if err := json.Unmarshal(bytes.TrimSpace(raw), &stored); err != nil || stored.Token == "" {
		return fmt.Errorf("%s is not a thothctl session; run `thothctl auth login` again", s.path)
	}
	if stored.Version != storedSessionVersion {
		return fmt.Errorf("unsupported thothctl session version %d in %s; run `thothctl auth login` again", stored.Version, s.path)
	}
	s.stored = stored
	return nil
}

// Token returns a current access token, renewing the session first when it
// expires within a minute. Concurrent requests share one renewal.
func (s *UserSession) Token(ctx context.Context, httpClient *http.Client) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.needsRenewal() {
		return s.stored.Token, nil
	}
	// thothctl may have renewed it since this run started.
	if err := s.reload(); err == nil && !s.needsRenewal() {
		return s.stored.Token, nil
	}
	if s.stored.RefreshToken == "" {
		return "", errors.New("the thothctl sign-in has expired; run `thothctl auth login` again")
	}
	if err := s.renew(ctx, httpClient); err != nil {
		// WorkOS rotates refresh tokens: if thothctl renewed at the same
		// time, its session is in the file now.
		if reloadErr := s.reload(); reloadErr == nil && !s.needsRenewal() {
			return s.stored.Token, nil
		}
		return "", fmt.Errorf("the thothctl sign-in could not be renewed (%v); run `thothctl auth login` again", err)
	}
	return s.stored.Token, nil
}

func (s *UserSession) needsRenewal() bool {
	return s.stored.ExpiresAtUnix != 0 && !s.now().Add(sessionRenewMargin).Before(time.Unix(s.stored.ExpiresAtUnix, 0))
}

func (s *UserSession) renew(ctx context.Context, httpClient *http.Client) error {
	base := strings.TrimRight(s.stored.GovAPIURL, "/")
	endpoint := base + "/" + url.PathEscape(s.stored.TenantID) + "/thoth/auth/cli/refresh"
	if s.renewURL != nil {
		endpoint = s.renewURL(base, s.stored.TenantID)
	}
	body, _ := json.Marshal(map[string]string{"refresh_token": s.stored.RefreshToken, "organization_id": s.stored.OrganizationID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("renewal refused with status %d", resp.StatusCode)
	}
	var out struct {
		AccessToken    string `json:"access_token"`
		RefreshToken   string `json:"refresh_token"`
		OrganizationID string `json:"organization_id"`
		ExpiresAtUnix  int64  `json:"expires_at_unix"`
	}
	if err := json.Unmarshal(data, &out); err != nil || strings.TrimSpace(out.AccessToken) == "" {
		return errors.New("renewal returned no access token")
	}
	if out.OrganizationID != s.stored.OrganizationID {
		return errors.New("renewal returned a different organization")
	}
	renewed := s.stored
	renewed.Token, renewed.ExpiresAtUnix = strings.TrimSpace(out.AccessToken), out.ExpiresAtUnix
	renewed.RefreshToken = strings.TrimSpace(out.RefreshToken)
	if err := writePrivateFile(s.path, renewed); err != nil {
		return err
	}
	s.stored = renewed
	return nil
}

// writePrivateFile replaces the session file atomically with mode 0600, as
// thothctl does, so neither ever reads a half-written session.
func writePrivateFile(path string, session storedSession) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".session-*")
	if err != nil {
		return fmt.Errorf("save the renewed thothctl session: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// StepUpProof returns thothctl's cached step-up proof for this GovAPI and
// tenant, when it is valid for at least another half minute.
func (s *UserSession) StepUpProof() string {
	if s.stepUp == "" {
		return ""
	}
	raw, err := os.ReadFile(s.stepUp)
	if err != nil {
		return ""
	}
	var cache struct {
		Proofs map[string]struct {
			Proof         string `json:"proof"`
			ExpiresAtUnix int64  `json:"expires_at_unix"`
		} `json:"proofs"`
	}
	if json.Unmarshal(raw, &cache) != nil {
		return ""
	}
	scope := strings.TrimRight(s.stored.GovAPIURL, "/") + "/" + s.stored.TenantID
	entry, ok := cache.Proofs[scope]
	if !ok || !s.now().Add(stepUpProofMinValidity).Before(time.Unix(entry.ExpiresAtUnix, 0)) {
		return ""
	}
	return entry.Proof
}

// TenantID is the workspace the session belongs to.
func (s *UserSession) TenantID() string { return s.stored.TenantID }
