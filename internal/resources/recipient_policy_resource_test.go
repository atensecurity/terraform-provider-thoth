package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

type recipientPolicyAPI struct {
	mu   sync.Mutex
	puts []map[string]any
}

func (a *recipientPolicyAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant-a/thoth/settings/recipient-policy" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		current := map[string]any{"mode": "observe", "internal_domains": []any{}, "allowed_external_domains": []any{}, "allowed_destinations": []any{}, "default": true, "internal_domains_source": "sign_in_domains"}
		if r.Method == http.MethodPut {
			body := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			a.puts = append(a.puts, body)
		}
		if n := len(a.puts); n > 0 {
			last := a.puts[n-1]
			source := "sign_in_domains"
			if domains, _ := last["internal_domains"].([]any); len(domains) > 0 {
				source = "setting"
			}
			current = map[string]any{"mode": last["mode"], "internal_domains": last["internal_domains"], "allowed_external_domains": last["allowed_external_domains"], "allowed_destinations": last["allowed_destinations"], "default": false, "internal_domains_source": source}
		}
		_ = json.NewEncoder(w).Encode(current)
	})
}

func newRecipientPolicyResource(t *testing.T, api *recipientPolicyAPI) *recipientPolicyResource {
	t.Helper()
	server := httptest.NewServer(api.handler(t))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	return &recipientPolicyResource{client: c, tenantID: "tenant-a"}
}

func TestRecipientPolicyApplySendsModeAndEveryList(t *testing.T) {
	api := &recipientPolicyAPI{}
	r := newRecipientPolicyResource(t, api)
	got, err := r.apply(context.Background(), "enforce", []string{"acme.example"}, []string{"partner.example"}, []string{"patient-portal"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode.ValueString() != "enforce" || got.InternalDomainsSource.ValueString() != "setting" || len(got.AllowedExternalDomains.Elements()) != 1 {
		t.Fatalf("unexpected state %+v", got)
	}
	put := api.puts[0]
	if put["mode"] != "enforce" || len(put["internal_domains"].([]any)) != 1 || put["allowed_destinations"].([]any)[0] != "patient-portal" {
		t.Fatalf("unexpected request %+v", put)
	}
}

func TestRecipientPolicyDestroyRestoresObserveAndSignInDomains(t *testing.T) {
	api := &recipientPolicyAPI{}
	r := newRecipientPolicyResource(t, api)
	if _, err := r.apply(context.Background(), "enforce", []string{"acme.example"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("delete failed: %v", resp.Diagnostics)
	}
	last := api.puts[len(api.puts)-1]
	if last["mode"] != "observe" || len(last["internal_domains"].([]any)) != 0 || len(last["allowed_external_domains"].([]any)) != 0 {
		t.Fatalf("delete should restore the defaults, sent %+v", last)
	}
}

func TestRecipientPolicyReadsTheDefaultsWhenUnset(t *testing.T) {
	got := flattenRecipientPolicy(map[string]any{}, "tenant-a")
	if got.Mode.ValueString() != "observe" || got.InternalDomainsSource.ValueString() != "sign_in_domains" || len(got.InternalDomains.Elements()) != 0 {
		t.Fatalf("unexpected defaults %+v", got)
	}
}
