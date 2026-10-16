package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestToolClassificationCRUDAndAuthorizationErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant/thoth/tool-classifications" && r.URL.Path != "/tenant/thoth/tool-classifications/decl" {
			t.Errorf("unscoped path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer admin-session" {
			t.Error("missing admin authentication")
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 2 || body["tool_name"] != "orders.list" {
				t.Errorf("unexpected body %#v", body)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "decl", "tool_name": "orders.list", "classes": []string{"read"}})
	}))
	defer server.Close()
	c, err := New(Config{BaseURL: server.URL, TenantID: "tenant", AuthToken: "admin-session"})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodPut, http.MethodDelete} {
		id := "decl"
		var payload map[string]any
		if method == http.MethodPost {
			id = ""
		}
		if method == http.MethodPost || method == http.MethodPut {
			payload = map[string]any{"tool_name": "orders.list", "classes": []string{"read"}}
		}
		if _, err := c.ToolClassification(context.Background(), method, id, payload); err != nil {
			t.Fatal(err)
		}
	}
}
