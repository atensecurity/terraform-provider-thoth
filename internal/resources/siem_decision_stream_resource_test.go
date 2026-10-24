package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

type siemStreamAPI struct {
	mu   sync.Mutex
	puts []map[string]any
}

func (a *siemStreamAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant-a/thoth/settings/siem/decision-stream" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		current := map[string]any{"enabled": false, "decisions": "non_allow", "allow_sample_rate": 1.0,
			"delivery": map[string]any{"destination_configured": true, "failed_last_24h": 0}}
		if r.Method == http.MethodPut {
			body := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			a.puts = append(a.puts, body)
		}
		if n := len(a.puts); n > 0 {
			for key, value := range a.puts[n-1] {
				current[key] = value
			}
		}
		_ = json.NewEncoder(w).Encode(current)
	})
}

func newSIEMStreamResource(t *testing.T, api *siemStreamAPI) *siemDecisionStreamResource {
	t.Helper()
	server := httptest.NewServer(api.handler(t))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	return &siemDecisionStreamResource{client: c, tenantID: "tenant-a"}
}

func TestSIEMDecisionStreamApplySendsTheWholeChoice(t *testing.T) {
	api := &siemStreamAPI{}
	r := newSIEMStreamResource(t, api)
	got, err := r.apply(context.Background(), siemDecisionStreamModel{
		Enabled: types.BoolValue(true), Decisions: types.StringValue("all"), AllowSampleRate: types.Float64Value(0.25),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled.ValueBool() || got.Decisions.ValueString() != "all" || got.AllowSampleRate.ValueFloat64() != 0.25 || got.ID.ValueString() != "tenant-a" {
		t.Fatalf("unexpected state %+v", got)
	}
	if len(api.puts) != 1 || api.puts[0]["enabled"] != true || api.puts[0]["decisions"] != "all" || api.puts[0]["allow_sample_rate"] != 0.25 {
		t.Fatalf("unexpected request %+v", api.puts)
	}
}

func TestSIEMDecisionStreamDestroyTurnsItOff(t *testing.T) {
	api := &siemStreamAPI{}
	r := newSIEMStreamResource(t, api)
	if _, err := r.apply(context.Background(), siemDecisionStreamModel{
		Enabled: types.BoolValue(true), Decisions: types.StringValue("all"), AllowSampleRate: types.Float64Value(0.5),
	}); err != nil {
		t.Fatal(err)
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("delete failed: %v", resp.Diagnostics)
	}
	last := api.puts[len(api.puts)-1]
	if last["enabled"] != false || last["decisions"] != "non_allow" || last["allow_sample_rate"] != 1.0 {
		t.Fatalf("destroy should turn the stream off with defaults, sent %+v", last)
	}
}

func TestSIEMDecisionStreamFlattenDefaults(t *testing.T) {
	got := flattenSIEMDecisionStream(map[string]any{}, "tenant-a")
	if got.Enabled.ValueBool() || got.Decisions.ValueString() != "non_allow" || got.AllowSampleRate.ValueFloat64() != 1 {
		t.Fatalf("empty responses read as off with defaults, got %+v", got)
	}
}
