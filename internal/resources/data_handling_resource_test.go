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

type dataHandlingAPI struct {
	mu   sync.Mutex
	puts []map[string]any
}

func (a *dataHandlingAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant-a/thoth/settings/data-handling" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		current := map[string]any{"tool_arguments": "hash", "prompts": "drop", "default": true}
		if r.Method == http.MethodPut {
			body := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			a.puts = append(a.puts, body)
			current = map[string]any{"tool_arguments": body["tool_arguments"], "prompts": body["prompts"], "default": false}
		} else if n := len(a.puts); n > 0 {
			current = map[string]any{"tool_arguments": a.puts[n-1]["tool_arguments"], "prompts": a.puts[n-1]["prompts"], "default": false}
		}
		_ = json.NewEncoder(w).Encode(current)
	})
}

func newDataHandlingResource(t *testing.T, api *dataHandlingAPI) *dataHandlingResource {
	t.Helper()
	server := httptest.NewServer(api.handler(t))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	return &dataHandlingResource{client: c, tenantID: "tenant-a"}
}

func TestDataHandlingApplySendsBothChoices(t *testing.T) {
	api := &dataHandlingAPI{}
	r := newDataHandlingResource(t, api)

	got, err := r.apply(context.Background(), "store", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if got.ToolArguments.ValueString() != "store" || got.Prompts.ValueString() != "hash" || got.ID.ValueString() != "tenant-a" {
		t.Fatalf("unexpected state %+v", got)
	}
	if len(api.puts) != 1 || api.puts[0]["tool_arguments"] != "store" || api.puts[0]["prompts"] != "hash" {
		t.Fatalf("unexpected request %+v", api.puts)
	}
}

func TestDataHandlingDestroyRestoresThePrivateDefaults(t *testing.T) {
	api := &dataHandlingAPI{}
	r := newDataHandlingResource(t, api)
	if _, err := r.apply(context.Background(), "store", "store"); err != nil {
		t.Fatal(err)
	}

	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("delete failed: %v", resp.Diagnostics)
	}
	last := api.puts[len(api.puts)-1]
	if last["tool_arguments"] != "hash" || last["prompts"] != "drop" {
		t.Fatalf("destroy should restore hash/drop, sent %+v", last)
	}
}

func TestDataHandlingFlattenFallsBackToDefaults(t *testing.T) {
	got := flattenDataHandling(map[string]any{}, "tenant-a")
	if got.ToolArguments.ValueString() != "hash" || got.Prompts.ValueString() != "drop" {
		t.Fatalf("empty responses read as the private defaults, got %+v", got)
	}
}
