package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRetryMaxAttempts = 4
	defaultRetryBaseDelay   = 300 * time.Millisecond
	defaultRetryMaxDelay    = 5 * time.Second
	defaultRequestTimeout   = 30 * time.Second
)

// Config defines the client configuration.
type Config struct {
	BaseURL   string
	TenantID  string
	AuthToken string
	APIKey    string
	// Session is a signed-in user's thothctl session (user_session.go).
	Session               *UserSession
	UserAgent             string
	ProvisionedVia        string
	Provisioner           string
	ProvisionerVersion    string
	RetryMaxAttempts      int
	RetryBaseDelay        time.Duration
	RetryMaxDelay         time.Duration
	RequestTimeout        time.Duration
	InsecureSkipTLSVerify bool
}

// APIError is returned for non-2xx responses.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	Body       string
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	if e.Code != "" {
		return fmt.Sprintf("thoth API error (%d %s): %s", e.StatusCode, e.Code, e.Message)
	}
	if e.Message != "" {
		return fmt.Sprintf("thoth API error (%d): %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("thoth API error (%d)", e.StatusCode)
}

// Client is the GovAPI client used by resources/data sources.
type Client struct {
	baseURL          string
	tenantID         string
	authToken        string
	apiKey           string
	session          *UserSession
	userAgent        string
	provisionedVia   string
	provisioner      string
	provisionerVer   string
	httpClient       *http.Client
	retryMaxAttempts int
	retryBaseDelay   time.Duration
	retryMaxDelay    time.Duration
}

// New creates a client with retry/backoff and context-aware HTTP requests.
func New(cfg Config) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		return nil, errors.New("api_base_url cannot be empty")
	}
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("invalid api_base_url: %w", err)
	}

	tenantID := strings.TrimSpace(cfg.TenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id cannot be empty")
	}
	authToken := strings.TrimSpace(cfg.AuthToken)
	apiKey := strings.TrimSpace(cfg.APIKey)
	configured := 0
	for _, set := range []bool{authToken != "", apiKey != "", cfg.Session != nil} {
		if set {
			configured++
		}
	}
	if configured == 0 {
		return nil, errors.New("configure an auth token, an org API key or a thothctl session")
	}
	if configured > 1 {
		return nil, errors.New("configure only one auth method: auth token, org API key or thothctl session")
	}

	retryMaxAttempts := cfg.RetryMaxAttempts
	if retryMaxAttempts <= 0 {
		retryMaxAttempts = defaultRetryMaxAttempts
	}
	if retryMaxAttempts > 10 {
		retryMaxAttempts = 10
	}

	retryBaseDelay := cfg.RetryBaseDelay
	if retryBaseDelay <= 0 {
		retryBaseDelay = defaultRetryBaseDelay
	}
	retryMaxDelay := cfg.RetryMaxDelay
	if retryMaxDelay <= 0 {
		retryMaxDelay = defaultRetryMaxDelay
	}
	if retryBaseDelay > retryMaxDelay {
		retryBaseDelay = retryMaxDelay
	}

	requestTimeout := cfg.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = defaultRequestTimeout
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
	if cfg.InsecureSkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	}

	return &Client{
		baseURL:          baseURL,
		tenantID:         tenantID,
		authToken:        authToken,
		session:          cfg.Session,
		apiKey:           apiKey,
		userAgent:        strings.TrimSpace(cfg.UserAgent),
		provisionedVia:   strings.TrimSpace(strings.ToLower(cfg.ProvisionedVia)),
		provisioner:      strings.TrimSpace(cfg.Provisioner),
		provisionerVer:   strings.TrimSpace(cfg.ProvisionerVersion),
		httpClient:       &http.Client{Timeout: requestTimeout, Transport: transport},
		retryMaxAttempts: retryMaxAttempts,
		retryBaseDelay:   retryBaseDelay,
		retryMaxDelay:    retryMaxDelay,
	}, nil
}

// TenantID returns the configured tenant scope.
func (c *Client) TenantID() string {
	return c.tenantID
}

func (c *Client) tenantPath(path string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(path), "/")
	return fmt.Sprintf("/%s/thoth/%s", c.tenantID, trimmed)
}

func (c *Client) governancePath(path string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(path), "/")
	return fmt.Sprintf("/%s/governance/%s", c.tenantID, trimmed)
}

func (c *Client) billingPath(path string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(path), "/")
	return fmt.Sprintf("/%s/billing/%s", c.tenantID, trimmed)
}

func (c *Client) doJSON(
	ctx context.Context,
	method string,
	path string,
	query map[string]string,
	requestBody any,
	responseBody any,
	retryable bool,
) error {
	fullURL, err := c.buildURL(path, query)
	if err != nil {
		return err
	}

	var payload []byte
	if requestBody != nil {
		payload, err = json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
	}

	for attempt := 1; attempt <= c.retryMaxAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		var bodyReader io.Reader
		if payload != nil {
			bodyReader = bytes.NewReader(payload)
		}

		req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		switch {
		case c.apiKey != "":
			req.Header.Set("X-Api-Key", c.apiKey)
		case c.session != nil:
			token, err := c.session.Token(ctx, c.httpClient)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+token)
			if proof := c.session.StepUpProof(); proof != "" {
				req.Header.Set(stepUpProofHeader, proof)
			}
		default:
			req.Header.Set("Authorization", "Bearer "+c.authToken)
		}
		if c.userAgent != "" {
			req.Header.Set("User-Agent", c.userAgent)
		}
		if c.provisionedVia != "" {
			req.Header.Set("X-Aten-Provisioned-Via", c.provisionedVia)
		}
		if c.provisioner != "" {
			req.Header.Set("X-Aten-Provisioner", c.provisioner)
		}
		if c.provisionerVer != "" {
			req.Header.Set("X-Aten-Provisioner-Version", c.provisionerVer)
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if retryable && attempt < c.retryMaxAttempts && isRetryableNetError(err) {
				if sleepErr := c.waitBackoff(ctx, attempt); sleepErr != nil {
					return sleepErr
				}
				continue
			}
			return fmt.Errorf("request failed: %w", err)
		}

		respBytes, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read response body: %w", readErr)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if responseBody != nil && len(respBytes) > 0 {
				if err := json.Unmarshal(respBytes, responseBody); err != nil {
					return fmt.Errorf("decode response: %w", err)
				}
			}
			return nil
		}

		apiErr := decodeAPIError(resp.StatusCode, respBytes)
		c.explainStepUp(apiErr)
		if retryable && attempt < c.retryMaxAttempts && isRetryableStatus(resp.StatusCode) {
			if sleepErr := c.waitBackoff(ctx, attempt); sleepErr != nil {
				return sleepErr
			}
			continue
		}

		return apiErr
	}

	return errors.New("max retry attempts exceeded")
}

func (c *Client) waitBackoff(ctx context.Context, attempt int) error {
	multiplier := math.Pow(2, float64(attempt-1))
	delay := time.Duration(float64(c.retryBaseDelay) * multiplier)
	if delay > c.retryMaxDelay {
		delay = c.retryMaxDelay
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) buildURL(path string, query map[string]string) (string, error) {
	rel := strings.TrimSpace(path)
	if rel == "" {
		return "", errors.New("path cannot be empty")
	}
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}

	parsed, err := url.Parse(c.baseURL + rel)
	if err != nil {
		return "", fmt.Errorf("build url: %w", err)
	}

	if len(query) > 0 {
		vals := parsed.Query()
		for k, v := range query {
			if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
				continue
			}
			vals.Set(k, v)
		}
		parsed.RawQuery = vals.Encode()
	}

	return parsed.String(), nil
}

func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func isRetryableNetError(err error) bool {
	var nerr net.Error
	if errors.As(err, &nerr) {
		return nerr.Timeout() || nerr.Temporary()
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return true
	}
	return false
}

func decodeAPIError(status int, body []byte) error {
	apiErr := &APIError{StatusCode: status, Body: strings.TrimSpace(string(body))}
	if len(body) == 0 {
		return apiErr
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return apiErr
	}
	if code, ok := payload["error"].(string); ok {
		apiErr.Code = code
	}
	if message, ok := payload["message"].(string); ok {
		apiErr.Message = message
	}
	if apiErr.Message == "" {
		if message, ok := payload["error_description"].(string); ok {
			apiErr.Message = message
		}
	}
	return apiErr
}

// explainStepUp says how to give a signed-in session the recent second factor
// a refusal asks for: a Terraform run cannot open the browser itself.
func (c *Client) explainStepUp(err error) {
	var apiErr *APIError
	if c.session == nil || !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden ||
		!strings.Contains(strings.ToLower(apiErr.Message), "step-up authentication") {
		return
	}
	apiErr.Message += ". Run `thothctl auth step-up --tenant-id " + c.tenantID + "`, confirm in the browser, then run Terraform again within 15 minutes"
}

// IsSignedInUser reports whether requests are made as a signed-in person
// (a thothctl session or an admin bearer token) rather than an API key.
func (c *Client) IsSignedInUser() bool { return c.apiKey == "" }

// IsNotFound reports whether err is an API 404.
func IsNotFound(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}

func (c *Client) GetTenantSettings(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("settings"), nil, nil, &out, true)
	return out, err
}

func (c *Client) UpdateTenantSettings(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPut, c.tenantPath("settings"), nil, payload, &out, true)
	return out, err
}

// orgSecurityPath is outside /thoth: GovAPI serves org security settings at
// /:tenant-id/settings/security.
func (c *Client) orgSecurityPath() string {
	return fmt.Sprintf("/%s/settings/security", c.tenantID)
}

func (c *Client) GetOrgSecuritySettings(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.orgSecurityPath(), nil, nil, &out, true)
	return out, err
}

func (c *Client) UpdateOrgSecuritySettings(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPut, c.orgSecurityPath(), nil, payload, &out, true)
	return out, err
}

func (c *Client) DeleteOrgSecuritySettings(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodDelete, c.orgSecurityPath(), nil, nil, nil, true)
}

func (c *Client) TestWebhook(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("settings/webhook/test"), nil, map[string]any{}, &out, false)
	return out, err
}

func (c *Client) BackfillGovernanceEvidence(
	ctx context.Context,
	query map[string]string,
	payload map[string]any,
) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(
		ctx,
		http.MethodPost,
		c.governancePath("evidence/thoth/backfill"),
		query,
		payload,
		&out,
		false,
	)
	if err == nil {
		return out, nil
	}
	if !isEvidenceBackfillCompatibilityError(err) {
		return out, err
	}

	out = map[string]any{}
	err = c.doJSON(
		ctx,
		http.MethodPost,
		c.tenantPath("governance/evidence/thoth/backfill"),
		query,
		payload,
		&out,
		false,
	)
	return out, err
}

func isEvidenceBackfillCompatibilityError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusMethodNotAllowed
}

func (c *Client) ListMDMProviders(ctx context.Context) ([]map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("mdm/providers"), nil, nil, &out, true)
	if err != nil {
		return nil, err
	}
	return extractDataArray(out)
}

func (c *Client) UpsertMDMProvider(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("mdm/providers"), nil, payload, &out, true)
	return out, err
}

func (c *Client) StartMDMSync(ctx context.Context, provider string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("mdm/providers/%s/sync", strings.TrimSpace(provider)))
	err := c.doJSON(ctx, http.MethodPost, path, nil, map[string]any{}, &out, false)
	return out, err
}

func (c *Client) GetMDMSyncJob(ctx context.Context, jobID string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("mdm/sync-jobs/%s", strings.TrimSpace(jobID)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) ListBrowserProviders(ctx context.Context) ([]map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("browser/providers"), nil, nil, &out, true)
	if err != nil {
		return nil, err
	}
	return extractDataArray(out)
}

func (c *Client) UpsertBrowserProvider(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("browser/providers"), nil, payload, &out, true)
	return out, err
}

func (c *Client) ListBrowserPolicies(ctx context.Context, provider string) ([]map[string]any, error) {
	out := map[string]any{}
	query := map[string]string{}
	if strings.TrimSpace(provider) != "" {
		query["provider"] = strings.TrimSpace(provider)
	}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("browser/policies"), query, nil, &out, true)
	if err != nil {
		return nil, err
	}
	return extractDataArray(out)
}

func (c *Client) UpsertBrowserPolicy(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("browser/policies"), nil, payload, &out, true)
	return out, err
}

func (c *Client) ListBrowserEnrollments(ctx context.Context, provider, status string) ([]map[string]any, error) {
	out := map[string]any{}
	query := map[string]string{}
	if strings.TrimSpace(provider) != "" {
		query["provider"] = strings.TrimSpace(provider)
	}
	if strings.TrimSpace(status) != "" {
		query["status"] = strings.TrimSpace(status)
	}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("browser/enrollments"), query, nil, &out, true)
	if err != nil {
		return nil, err
	}
	return extractDataArray(out)
}

func (c *Client) UpsertBrowserEnrollment(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("browser/enrollments"), nil, payload, &out, true)
	return out, err
}

func (c *Client) ListMCPVendors(ctx context.Context, approved *bool) ([]map[string]any, error) {
	out := map[string]any{}
	query := map[string]string{}
	if approved != nil {
		query["approved"] = strconv.FormatBool(*approved)
	}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("mcp/vendors"), query, nil, &out, true)
	if err != nil {
		return nil, err
	}
	return extractDataArray(out)
}

func (c *Client) GetMCPVendor(ctx context.Context, vendorID string) (map[string]any, error) {
	normalized := strings.TrimSpace(vendorID)
	if normalized == "" {
		return nil, errors.New("vendor_id must be non-empty")
	}
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("mcp/vendors/%s", url.PathEscape(normalized)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) CreateMCPVendor(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("mcp/vendors"), nil, payload, &out, false)
	return out, err
}

func (c *Client) UpdateMCPVendor(ctx context.Context, vendorID string, payload map[string]any) (map[string]any, error) {
	normalized := strings.TrimSpace(vendorID)
	if normalized == "" {
		return nil, errors.New("vendor_id must be non-empty")
	}
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("mcp/vendors/%s", url.PathEscape(normalized)))
	err := c.doJSON(ctx, http.MethodPut, path, nil, payload, &out, false)
	return out, err
}

func (c *Client) DeleteMCPVendor(ctx context.Context, vendorID string) error {
	normalized := strings.TrimSpace(vendorID)
	if normalized == "" {
		return errors.New("vendor_id must be non-empty")
	}
	path := c.tenantPath(fmt.Sprintf("mcp/vendors/%s", url.PathEscape(normalized)))
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil, nil, false)
}

func (c *Client) GetMCPInventoryReport(ctx context.Context, windowHours int64) (map[string]any, error) {
	out := map[string]any{}
	query := map[string]string{}
	if windowHours > 0 {
		query["window_hours"] = strconv.FormatInt(windowHours, 10)
	}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("mcp/inventory/report"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetMCPInventoryDigest(ctx context.Context, windowHours int64) (map[string]any, error) {
	out := map[string]any{}
	query := map[string]string{}
	if windowHours > 0 {
		query["window_hours"] = strconv.FormatInt(windowHours, 10)
	}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("mcp/inventory/digest"), query, nil, &out, true)
	return out, err
}

func (c *Client) VerifyMCPCatalog(ctx context.Context, environment string, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	query := map[string]string{}
	if env := strings.TrimSpace(environment); env != "" {
		query["env"] = env
	}
	if payload == nil {
		payload = map[string]any{}
	}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("mcp/catalog/verify"), query, payload, &out, false)
	return out, err
}

func (c *Client) ListAPIKeys(ctx context.Context) ([]map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("api-keys"), nil, nil, &out, true)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0)
	if raw, ok := out["api_keys"].([]any); ok {
		for _, row := range raw {
			if m, ok := row.(map[string]any); ok {
				items = append(items, m)
			}
		}
	}
	return items, nil
}

func (c *Client) CreateAPIKey(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("api-keys"), nil, payload, &out, false)
	return out, err
}

func (c *Client) RevokeAPIKey(ctx context.Context, keyID string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("api-keys/%s", strings.TrimSpace(keyID)))
	err := c.doJSON(ctx, http.MethodDelete, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) AuthorizeAPIKey(ctx context.Context, keyID string, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("api-keys/%s/authorize", strings.TrimSpace(keyID)))
	err := c.doJSON(ctx, http.MethodPost, path, nil, payload, &out, false)
	return out, err
}

func (c *Client) GetAPIKeyMetrics(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("api-keys/metrics"), nil, nil, &out, true)
	return out, err
}

func (c *Client) GetEvidenceChain(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("evidence/chain"), query, nil, &out, true)
	return out, err
}

func (c *Client) VerifyEvidenceChain(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.governancePath("evidence/verify-chain"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetSessionEvidenceBundle(ctx context.Context, sessionID string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("sessions/%s/evidence-bundle", strings.TrimSpace(sessionID)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

// CreateEvidencePack queues a signed evidence pack. Empty bounds mean the
// previous calendar month. A 409 carries the workspace's pack in progress.
func (c *Client) CreateEvidencePack(ctx context.Context, periodStart, periodEnd string) (map[string]any, error) {
	out := map[string]any{}
	body := map[string]string{"period_start": periodStart, "period_end": periodEnd}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("evidence/packs"), nil, body, &out, false)
	return out, err
}

func (c *Client) ListEvidencePacks(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("evidence/packs"), nil, nil, &out, true)
	return out, err
}

// GetAgentObserveSummary reads what enforcing would have changed for an agent
// in observe mode, with the Ready to enforce verdict. days 0 is the default (7).
func (c *Client) GetAgentObserveSummary(ctx context.Context, agentID string, days int64) (map[string]any, error) {
	normalized := strings.TrimSpace(agentID)
	if normalized == "" {
		return nil, errors.New("agent_id must be non-empty")
	}
	query := map[string]string{}
	if days > 0 {
		query["days"] = fmt.Sprintf("%d", days)
	}
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("v1/agents/%s/observe-summary", url.PathEscape(normalized)))
	err := c.doJSON(ctx, http.MethodGet, path, query, nil, &out, true)
	return out, err
}

func (c *Client) GetSessionForensics(ctx context.Context, sessionID string) (map[string]any, error) {
	normalized := strings.TrimSpace(sessionID)
	if normalized == "" {
		return nil, errors.New("session_id must be non-empty")
	}
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("sessions/%s/forensics", url.PathEscape(normalized)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) GetIncidentForensics(ctx context.Context, incidentID string) (map[string]any, error) {
	normalized := strings.TrimSpace(incidentID)
	if normalized == "" {
		return nil, errors.New("incident_id must be non-empty")
	}
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("incidents/%s/forensics", url.PathEscape(normalized)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) GetAgentLatestForensics(ctx context.Context, agentID string) (map[string]any, error) {
	normalized := strings.TrimSpace(agentID)
	if normalized == "" {
		return nil, errors.New("agent_id must be non-empty")
	}
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("agents/%s/forensics/latest", url.PathEscape(normalized)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) GetBillingPricing(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.billingPath("pricing"), nil, nil, &out, true)
	return out, err
}

func (c *Client) GetBillingMonthlyCost(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.billingPath("monthly-cost"), nil, nil, &out, true)
	return out, err
}

func (c *Client) GetBillingCreditBank(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.billingPath("credit-bank"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetBillingEstimate(ctx context.Context, payload map[string]any, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	if payload == nil {
		payload = map[string]any{}
	}
	err := c.doJSON(ctx, http.MethodPost, c.billingPath("estimate"), query, payload, &out, false)
	return out, err
}

func (c *Client) UpdateBillingOverageCap(ctx context.Context, overageCapUSD float64) (map[string]any, error) {
	out := map[string]any{}
	payload := map[string]any{
		"overage_cap_usd": overageCapUSD,
	}
	err := c.doJSON(ctx, http.MethodPut, c.billingPath("overage-cap"), nil, payload, &out, false)
	return out, err
}

// GetDataHandling reads what Thoth keeps of tool arguments and prompts.
func (c *Client) GetDataHandling(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("settings/data-handling"), nil, nil, &out, true)
	return out, err
}

// UpdateDataHandling sets what Thoth keeps of tool arguments and prompts.
// GetSIEMDecisionStream reads which decisions reach the workspace's SIEM and
// how delivery is going.
// GetAgentEnforcement reads an agent's enforcement mode (observe | enforce) and
// what a high risk score does while enforcing (hold | deny).
func (c *Client) GetAgentEnforcement(ctx context.Context, agentID string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("agents/"+url.PathEscape(agentID)+"/enforcement-mode"), nil, nil, &out, true)
	return out, err
}

// GetAgent reads a registered agent: display name, owner, approved scope and status.
func (c *Client) GetAgent(ctx context.Context, agentID string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("agents/"+url.PathEscape(agentID)), nil, nil, &out, true)
	return out, err
}

// RegisterAgent registers an agent, or updates its registration. It never
// sets the enforcement mode (thoth_agent_enforcement does) and never changes
// a quarantine.
func (c *Client) RegisterAgent(ctx context.Context, agentID, displayName, ownerEmail string, approvedScope []string) (map[string]any, error) {
	out := map[string]any{}
	payload := map[string]any{"display_name": displayName, "owner_email": ownerEmail, "approved_scope": approvedScope}
	err := c.doJSON(ctx, http.MethodPut, c.tenantPath("agents/"+url.PathEscape(agentID)+"/register"), nil, payload, &out, false)
	return out, err
}

// UpdateAgentEnforcement sets an agent's enforcement mode and, when
// afterDecline is set, what a person declining one of its held actions does
// (raise, stop or quarantine). minutes is sent only with raise; an empty
// afterDecline leaves the stored setting unchanged.
func (c *Client) UpdateAgentEnforcement(ctx context.Context, agentID, mode, highRiskAction, afterDecline string, minutes int64) (map[string]any, error) {
	out := map[string]any{}
	payload := map[string]any{"enforcement_mode": mode, "high_risk_action": highRiskAction}
	if afterDecline != "" {
		payload["after_decline"] = afterDecline
		if afterDecline == "raise" && minutes != 0 {
			payload["after_decline_minutes"] = minutes
		}
	}
	err := c.doJSON(ctx, http.MethodPut, c.tenantPath("agents/"+url.PathEscape(agentID)+"/enforcement-mode"), nil, payload, &out, false)
	return out, err
}

func (c *Client) GetSIEMDecisionStream(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("settings/siem/decision-stream"), nil, nil, &out, true)
	return out, err
}

// UpdateSIEMDecisionStream sets the decision stream. Turning it on needs a
// SIEM destination (thoth_siem_settings) first.
func (c *Client) UpdateSIEMDecisionStream(ctx context.Context, enabled bool, decisions string, allowSampleRate float64) (map[string]any, error) {
	out := map[string]any{}
	payload := map[string]any{"enabled": enabled, "decisions": decisions, "allow_sample_rate": allowSampleRate}
	err := c.doJSON(ctx, http.MethodPut, c.tenantPath("settings/siem/decision-stream"), nil, payload, &out, false)
	return out, err
}

func (c *Client) UpdateDataHandling(ctx context.Context, toolArguments, prompts string) (map[string]any, error) {
	out := map[string]any{}
	payload := map[string]any{"tool_arguments": toolArguments, "prompts": prompts}
	err := c.doJSON(ctx, http.MethodPut, c.tenantPath("settings/data-handling"), nil, payload, &out, false)
	return out, err
}

func (c *Client) ListBillingInvoices(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.billingPath("invoices"), query, nil, &out, true)
	return out, err
}

func (c *Client) ListBillingReports(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.billingPath("reports"), nil, nil, &out, true)
	return out, err
}

func (c *Client) GetBillingReport(ctx context.Context, year, month int64) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(
		ctx,
		http.MethodGet,
		c.billingPath(fmt.Sprintf("reports/%d/%d", year, month)),
		nil,
		nil,
		&out,
		true,
	)
	return out, err
}

func (c *Client) ListBillingArtifacts(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.billingPath("artifacts"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetBillingArtifact(ctx context.Context, year, month int64) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(
		ctx,
		http.MethodGet,
		c.billingPath(fmt.Sprintf("artifacts/%d/%d", year, month)),
		nil,
		nil,
		&out,
		true,
	)
	return out, err
}

func (c *Client) ListGovernanceFeed(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("governance/feed"), query, nil, &out, true)
	return out, err
}

func (c *Client) ListGovernanceTools(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("governance/tools"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetGovernanceEvidenceSLOs(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("governance/evidence-slos"), query, nil, &out, true)
	return out, err
}

func (c *Client) BackfillGovernanceDecisionFields(
	ctx context.Context,
	query map[string]string,
	payload map[string]any,
) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(
		ctx,
		http.MethodPost,
		c.tenantPath("governance/backfill-decision-fields"),
		query,
		payload,
		&out,
		false,
	)
	return out, err
}

func (c *Client) TriggerPolicySync(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("policies/sync"), nil, map[string]any{}, &out, false)
	return out, err
}

func (c *Client) GetPolicySyncStatus(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("policies/sync/status"), nil, nil, &out, true)
	return out, err
}

func (c *Client) CreatePolicyException(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("policy-exceptions"), nil, payload, &out, false)
	return out, err
}

func (c *Client) ListPolicyExceptions(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("policy-exceptions"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetPolicyException(ctx context.Context, requestID string) (map[string]any, error) {
	normalized := strings.TrimSpace(requestID)
	if normalized == "" {
		return nil, errors.New("request_id must be non-empty")
	}
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("policy-exceptions/%s", url.PathEscape(normalized)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) ReviewPolicyException(
	ctx context.Context,
	requestID string,
	payload map[string]any,
) (map[string]any, error) {
	normalized := strings.TrimSpace(requestID)
	if normalized == "" {
		return nil, errors.New("request_id must be non-empty")
	}
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("policy-exceptions/%s/review", url.PathEscape(normalized)))
	err := c.doJSON(ctx, http.MethodPatch, path, nil, payload, &out, false)
	return out, err
}

func (c *Client) ListPolicyChangeArtifacts(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("policy-change-artifacts"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetPolicyChangeArtifact(ctx context.Context, requestID string) (map[string]any, error) {
	normalized := strings.TrimSpace(requestID)
	if normalized == "" {
		return nil, errors.New("request_id must be non-empty")
	}
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("policy-change-artifacts/%s", url.PathEscape(normalized)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) GeneratePolicyChangeArtifact(
	ctx context.Context,
	requestID string,
	payload map[string]any,
) (map[string]any, error) {
	normalized := strings.TrimSpace(requestID)
	if normalized == "" {
		return nil, errors.New("request_id must be non-empty")
	}
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("policy-change-artifacts/%s/generate", url.PathEscape(normalized)))
	err := c.doJSON(ctx, http.MethodPost, path, nil, payload, &out, false)
	return out, err
}

func (c *Client) ApplyPolicyChangeArtifact(
	ctx context.Context,
	requestID string,
	payload map[string]any,
) (map[string]any, error) {
	normalized := strings.TrimSpace(requestID)
	if normalized == "" {
		return nil, errors.New("request_id must be non-empty")
	}
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("policy-change-artifacts/%s/apply", url.PathEscape(normalized)))
	err := c.doJSON(ctx, http.MethodPost, path, nil, payload, &out, false)
	return out, err
}

func (c *Client) ListPolicyBundles(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("policy-bundles"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetPolicyBundle(ctx context.Context, bundleID string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("policy-bundles/%s", strings.TrimSpace(bundleID)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) CreatePolicyBundle(ctx context.Context, payload map[string]any, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("policy-bundles"), query, payload, &out, false)
	return out, err
}

func (c *Client) DeletePolicyBundle(ctx context.Context, bundleID string) error {
	path := c.tenantPath(fmt.Sprintf("policy-bundles/%s", strings.TrimSpace(bundleID)))
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil, nil, false)
}

// ListDecisionsPage reads one page of recorded enforcement decisions, newest
// first (GET /:tenant/thoth/v1/activity?type=decision). The query carries the
// filters, limit and cursor; the response has items and next_cursor.
func (c *Client) ListDecisionsPage(ctx context.Context, query map[string]string) (map[string]any, error) {
	q := map[string]string{"type": "decision"}
	for key, value := range query {
		q[key] = value
	}
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("v1/activity"), q, nil, &out, true)
	return out, err
}

func (c *Client) ListApprovalsWithQuery(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("approvals"), query, nil, &out, true)
	return out, err
}

func (c *Client) ResolveApproval(ctx context.Context, approvalID, decision string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("approvals/%s/resolve", strings.TrimSpace(approvalID)))
	payload := map[string]any{"decision": strings.TrimSpace(decision)}
	err := c.doJSON(ctx, http.MethodPost, path, nil, payload, &out, false)
	return out, err
}

func (c *Client) ListApprovals(ctx context.Context, status string) ([]map[string]any, error) {
	query := map[string]string{}
	if strings.TrimSpace(status) != "" {
		query["status"] = strings.TrimSpace(status)
	}
	out, err := c.ListApprovalsWithQuery(ctx, query)
	if err != nil {
		return nil, err
	}
	return extractDataArray(out)
}

func (c *Client) ApplyPackToAgent(ctx context.Context, agentID string, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("agents/%s/apply-pack", strings.TrimSpace(agentID)))
	err := c.doJSON(ctx, http.MethodPost, path, nil, payload, &out, false)
	return out, err
}

func (c *Client) ApplyPacksBulk(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("packs/apply"), nil, payload, &out, false)
	return out, err
}

func (c *Client) ListAgentPacks(ctx context.Context, agentID string) ([]map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("agents/%s/packs", strings.TrimSpace(agentID)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0)
	if raw, ok := out["packs"].([]any); ok {
		for _, row := range raw {
			if m, ok := row.(map[string]any); ok {
				items = append(items, m)
			}
		}
	}
	return items, nil
}

func (c *Client) RevokePackFromAgent(ctx context.Context, agentID, packID string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("agents/%s/packs/%s", strings.TrimSpace(agentID), strings.TrimSpace(packID)))
	err := c.doJSON(ctx, http.MethodDelete, path, nil, nil, &out, false)
	return out, err
}

func (c *Client) ListFleets(ctx context.Context) ([]map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("fleets"), nil, nil, &out, true)
	if err != nil {
		return nil, err
	}
	return extractDataArray(out)
}

func (c *Client) GetFleet(ctx context.Context, fleetID string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("fleets/%s", strings.TrimSpace(fleetID)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) CreateFleet(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("fleets"), nil, payload, &out, false)
	return out, err
}

func (c *Client) UpdateFleet(ctx context.Context, fleetID string, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("fleets/%s", strings.TrimSpace(fleetID)))
	err := c.doJSON(ctx, http.MethodPut, path, nil, payload, &out, false)
	return out, err
}

func (c *Client) DeleteFleet(ctx context.Context, fleetID string) error {
	path := c.tenantPath(fmt.Sprintf("fleets/%s", strings.TrimSpace(fleetID)))
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil, nil, false)
}

func (c *Client) ListGovernancePacks(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("packs"), nil, nil, &out, true)
	return out, err
}

func (c *Client) GetGovernancePackRules(ctx context.Context, packID string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("packs/%s/rules", strings.TrimSpace(packID)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) ListGovernancePackRuleVersions(ctx context.Context, packID string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("packs/%s/rules/history", strings.TrimSpace(packID)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) GetPackRuntimeStatus(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("packs/runtime-status"), query, nil, &out, true)
	return out, err
}

func (c *Client) ListEffectivePolicyBundles(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("policy-bundles/effective"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetDay7Report(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("reports/day7"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetReportsOverview(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("reports/overview"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetCostReport(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("reports/cost"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetExecutiveSummary(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(
		ctx,
		http.MethodGet,
		c.tenantPath("reports/executive-summary"),
		query,
		nil,
		&out,
		true,
	)
	return out, err
}

func (c *Client) GetBoardIncidentSummary(ctx context.Context, violationID string) (map[string]any, error) {
	out := map[string]any{}
	normalized := strings.TrimSpace(violationID)
	if normalized == "" {
		return nil, errors.New("violation_id must be non-empty")
	}
	path := c.tenantPath(fmt.Sprintf("reports/board-incident/%s", url.PathEscape(normalized)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) ListAIRSReports(ctx context.Context, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("reports"), query, nil, &out, true)
	return out, err
}

func (c *Client) GetAIRSReport(ctx context.Context, reportID string, query map[string]string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("reports/%s", strings.TrimSpace(reportID)))
	err := c.doJSON(ctx, http.MethodGet, path, query, nil, &out, true)
	return out, err
}

func (c *Client) ListEndpoints(ctx context.Context, env, fleetID string) ([]map[string]any, error) {
	out := map[string]any{}
	query := map[string]string{}
	if strings.TrimSpace(env) != "" {
		query["env"] = strings.TrimSpace(env)
	}
	if strings.TrimSpace(fleetID) != "" {
		query["fleet_id"] = strings.TrimSpace(fleetID)
	}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("endpoints"), query, nil, &out, true)
	if err != nil {
		return nil, err
	}
	return extractDataArray(out)
}

func (c *Client) GetEndpointStats(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("endpoints/stats"), nil, nil, &out, true)
	return out, err
}

func (c *Client) GetEndpoint(ctx context.Context, endpointID string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("endpoints/%s", strings.TrimSpace(endpointID)))
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out, err
}

func (c *Client) RegisterEndpoint(ctx context.Context, payload map[string]any) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodPost, c.tenantPath("endpoints"), nil, payload, &out, false)
	return out, err
}

func (c *Client) QuarantineEndpoint(ctx context.Context, endpointID string) (map[string]any, error) {
	out := map[string]any{}
	path := c.tenantPath(fmt.Sprintf("endpoints/%s/quarantine", strings.TrimSpace(endpointID)))
	err := c.doJSON(ctx, http.MethodPost, path, nil, nil, &out, false)
	return out, err
}

func extractDataArray(payload map[string]any) ([]map[string]any, error) {
	items := make([]map[string]any, 0)
	raw, ok := payload["data"]
	if !ok {
		return items, nil
	}
	rows, ok := raw.([]any)
	if !ok {
		return nil, errors.New("unexpected API response: data is not an array")
	}
	for _, row := range rows {
		m, ok := row.(map[string]any)
		if !ok {
			continue
		}
		items = append(items, m)
	}
	return items, nil
}

// GetComplianceCatalogue returns the running enforcement catalogue and declaration capability.
func (c *Client) GetComplianceCatalogue(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("compliance/catalogue"), nil, nil, &out, true)
	return out, err
}

// ToolClassification accesses the authenticated tenant's declaration registry.
func (c *Client) ToolClassification(ctx context.Context, method, id string, payload map[string]any) (map[string]any, error) {
	path := c.tenantPath("tool-classifications")
	if id != "" {
		path += "/" + url.PathEscape(id)
	}
	var out map[string]any
	err := c.doJSON(ctx, method, path, nil, payload, &out, true)
	return out, err
}
