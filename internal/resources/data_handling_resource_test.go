package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

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
			current = stored(body)
		} else if n := len(a.puts); n > 0 {
			current = stored(a.puts[n-1])
		}
		_ = json.NewEncoder(w).Encode(current)
	})
}

func stored(body map[string]any) map[string]any {
	return map[string]any{
		"tool_arguments": body["tool_arguments"], "prompts": body["prompts"], "default": false,
		"accept_local_scan": body["accept_local_scan"], "accepted_scanner_ruleset_hashes": body["accepted_scanner_ruleset_hashes"], "require_client_findings": body["require_client_findings"],
	}
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

	got, err := r.apply(context.Background(), "store", "hash", false, []string{}, false)
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
	if _, err := r.apply(context.Background(), "store", "store", true, []string{"abababababababababababababababababababababababababababababababab"}, true); err != nil {
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
	hashes, _ := last["accepted_scanner_ruleset_hashes"].([]any)
	if last["accept_local_scan"] != false || last["require_client_findings"] != false || len(hashes) != 0 {
		t.Fatalf("destroy should accept no local scan and require none, sent %+v", last)
	}
}

func TestDataHandlingFlattenFallsBackToDefaults(t *testing.T) {
	got := flattenDataHandling(map[string]any{}, "tenant-a")
	if got.ToolArguments.ValueString() != "hash" || got.Prompts.ValueString() != "drop" {
		t.Fatalf("empty responses read as the private defaults, got %+v", got)
	}
	if got.AcceptLocalScan.ValueBool() || got.RequireClientFindings.ValueBool() || len(got.AcceptedScannerRulesetHashes.Elements()) != 0 {
		t.Fatalf("empty responses accept no local scan and require none, got %+v", got)
	}
}

func TestDataHandlingApplySendsTheLocalScanChoices(t *testing.T) {
	api := &dataHandlingAPI{}
	r := newDataHandlingResource(t, api)
	hash := strings.Repeat("ab", 32)

	got, err := r.apply(context.Background(), "drop", "drop", true, []string{hash}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.AcceptLocalScan.ValueBool() || !got.RequireClientFindings.ValueBool() || len(got.AcceptedScannerRulesetHashes.Elements()) != 1 {
		t.Fatalf("unexpected state %+v", got)
	}
	sent := api.puts[0]
	hashes, _ := sent["accepted_scanner_ruleset_hashes"].([]any)
	if sent["accept_local_scan"] != true || sent["require_client_findings"] != true || len(hashes) != 1 || hashes[0] != hash {
		t.Fatalf("unexpected request %+v", sent)
	}
}

func TestDataHandlingSchemaRejectsMalformedHashes(t *testing.T) {
	resp := &resource.SchemaResponse{}
	(&dataHandlingResource{}).Schema(context.Background(), resource.SchemaRequest{}, resp)
	attribute := resp.Schema.Attributes["accepted_scanner_ruleset_hashes"].(schema.ListAttribute)
	for value, valid := range map[string]bool{strings.Repeat("ab", 32): true, strings.Repeat("AB", 32): false, "nope": false, strings.Repeat("ab", 31): false} {
		ok := true
		for _, v := range attribute.Validators {
			req := validator.ListRequest{Path: path.Root("accepted_scanner_ruleset_hashes"), ConfigValue: types.ListValueMust(types.StringType, []attr.Value{types.StringValue(value)})}
			out := &validator.ListResponse{}
			v.ValidateList(context.Background(), req, out)
			ok = ok && !out.Diagnostics.HasError()
		}
		if ok != valid {
			t.Fatalf("hash %q: valid=%v, want %v", value, ok, valid)
		}
	}
}
