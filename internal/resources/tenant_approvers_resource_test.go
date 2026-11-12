package resources

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

const approversTenant = "trantor"

// approversAPI replays the behaviour and JSON shapes of govapi's
// GetThothApprovers and UpdateThothApprovers (backend/go/cmd/govapi/thoth_approvers.go),
// not what the provider assumes:
//   - GET and PUT answer {user_ids, updated_by, updated_at, revision}; user_ids is always an
//     array and updated_at is null until the first save;
//   - PUT takes exactly {revision, user_ids}, refuses unknown fields (400), duplicates (400),
//     more than 50 (400), IDs that are not members (422) and a stale revision (409), and
//     answers errors as {"message": ...} (echo.HTTPError);
//   - an API key is refused on PUT with 403 "Sign in as an administrator to choose approvers".
type approversAPI struct {
	mu        sync.Mutex
	userIDs   []string
	updatedBy string
	updatedAt *time.Time
	revision  int64
	members   map[string]bool
	actor     string
	outage    bool
	calls     []string
	bodies    []map[string]any
	// beforePut runs inside the PUT before the revision check, to simulate a second admin saving.
	beforePut func(a *approversAPI)
}

func newApproversAPI(members ...string) *approversAPI {
	a := &approversAPI{members: map[string]bool{}, actor: "user_admin1"}
	for _, m := range members {
		a.members[m] = true
	}
	return a
}

func (a *approversAPI) current() map[string]any {
	ids := append([]string{}, a.userIDs...)
	var at any
	if a.updatedAt != nil {
		at = a.updatedAt.Format(time.RFC3339Nano)
	}
	return map[string]any{"user_ids": ids, "updated_by": a.updatedBy, "updated_at": at, "revision": a.revision}
}

func (a *approversAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fail := func(code int, msg string) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
		}
		a.calls = append(a.calls, r.Method+" "+r.URL.Path)
		if r.URL.Path != "/"+approversTenant+"/thoth/settings/approvers" {
			fail(404, "Not Found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(a.current())
		case http.MethodPut:
			if r.Header.Get("X-Api-Key") != "" {
				fail(403, "Sign in as an administrator to choose approvers")
				return
			}
			raw, _ := io.ReadAll(r.Body)
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			var in struct {
				Revision *int64    `json:"revision"`
				UserIDs  *[]string `json:"user_ids"`
			}
			if dec.Decode(&in) != nil || in.Revision == nil || *in.Revision < 0 || in.UserIDs == nil {
				fail(400, "Provide revision and user_ids; reload before saving")
				return
			}
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			a.bodies = append(a.bodies, body)
			if len(*in.UserIDs) > 50 {
				fail(400, "Choose at most 50 approvers")
				return
			}
			seen := map[string]bool{}
			for _, id := range *in.UserIDs {
				if !regexp.MustCompile(`^user_[A-Za-z0-9]{1,80}$`).MatchString(id) {
					fail(422, "Choose a verified active member of this organization")
					return
				}
				if seen[id] {
					fail(400, "Choose each approver once")
					return
				}
				seen[id] = true
			}
			if len(*in.UserIDs) > 0 {
				if a.outage {
					fail(503, "Approver verification is unavailable")
					return
				}
				for _, id := range *in.UserIDs {
					if !a.members[id] {
						fail(422, "Choose a verified active member of this organization")
						return
					}
				}
			}
			if a.beforePut != nil {
				a.beforePut(a)
			}
			if a.revision != *in.Revision {
				fail(409, "Approvers changed; reload before saving")
				return
			}
			now := time.Now().UTC()
			a.userIDs, a.updatedBy, a.updatedAt, a.revision = append([]string{}, *in.UserIDs...), a.actor, &now, *in.Revision+1
			_ = json.NewEncoder(w).Encode(a.current())
		default:
			fail(405, "Method Not Allowed")
		}
	})
}

func approversClient(t *testing.T, api *approversAPI, apiKey bool) *client.Client {
	t.Helper()
	server := httptest.NewServer(api.handler())
	t.Cleanup(server.Close)
	cfg := client.Config{BaseURL: server.URL, TenantID: approversTenant, AuthToken: "user-token"}
	if apiKey {
		cfg = client.Config{BaseURL: server.URL, TenantID: approversTenant, APIKey: "key"}
	}
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func approversResource(t *testing.T, api *approversAPI, apiKey bool) *tenantApproversResource {
	return &tenantApproversResource{client: approversClient(t, api, apiKey), tenantID: approversTenant}
}

func applyApprovers(r *tenantApproversResource, ids ...string) (tenantApproversModel, diag.Diagnostics) {
	var saved tenantApproversModel
	var diags diag.Diagnostics
	plan := tenantApproversModel{UserIDs: reviewerSet(ids...)}
	r.apply(context.Background(), func(_ context.Context, target any) diag.Diagnostics {
		*(target.(*tenantApproversModel)) = plan
		return nil
	}, func(m tenantApproversModel) diag.Diagnostics { saved = m; return nil }, &diags)
	return saved, diags
}

func TestTenantApproversCreateSendsTheRevisionItRead(t *testing.T) {
	api := newApproversAPI("user_ana", "user_bo")
	saved, diags := applyApprovers(approversResource(t, api, false), "user_bo", "user_ana")
	if diags.HasError() {
		t.Fatal(diags)
	}
	if len(api.bodies) != 1 || api.bodies[0]["revision"] != float64(0) || len(api.bodies[0]) != 2 {
		t.Fatalf("the body is exactly {revision, user_ids}: %v", api.bodies)
	}
	if !saved.UserIDs.Equal(reviewerSet("user_ana", "user_bo")) || saved.Revision.ValueInt64() != 1 ||
		saved.UpdatedBy.ValueString() != "user_admin1" || saved.UpdatedAt.ValueString() == "" || saved.ID.ValueString() != approversTenant {
		t.Fatalf("state %+v", saved)
	}
}

func TestTenantApproversUpdateReplacesTheWholeListAgainstTheCurrentRevision(t *testing.T) {
	api := newApproversAPI("user_ana", "user_bo", "user_cy")
	r := approversResource(t, api, false)
	if _, diags := applyApprovers(r, "user_ana", "user_bo"); diags.HasError() {
		t.Fatal(diags)
	}
	saved, diags := applyApprovers(r, "user_bo", "user_cy")
	if diags.HasError() {
		t.Fatal(diags)
	}
	if api.bodies[1]["revision"] != float64(1) || saved.Revision.ValueInt64() != 2 || !saved.UserIDs.Equal(reviewerSet("user_bo", "user_cy")) {
		t.Fatalf("bodies %v state %+v", api.bodies, saved)
	}
}

func TestTenantApproversStaleRevisionIsRefusedWithAClearMessage(t *testing.T) {
	api := newApproversAPI("user_ana", "user_bo")
	// A second admin saves between this apply's read and its save.
	api.beforePut = func(a *approversAPI) {
		a.beforePut = nil
		a.userIDs, a.revision = []string{"user_bo"}, a.revision+1
	}
	_, diags := applyApprovers(approversResource(t, api, false), "user_ana")
	if !diags.HasError() || !strings.Contains(diags.Errors()[0].Summary(), "changed while this apply ran") ||
		!strings.Contains(diags.Errors()[0].Detail(), "nothing was overwritten") {
		t.Fatalf("diags %v", diags)
	}
	if len(api.userIDs) != 1 || api.userIDs[0] != "user_bo" {
		t.Fatalf("the other admin's list stays: %v", api.userIDs)
	}
}

func TestTenantApproversReadShowsDriftAndAnUnsetList(t *testing.T) {
	api := newApproversAPI("user_ana")
	r := approversResource(t, api, false)
	// Never saved: user_ids is [] and updated_at is null on the wire.
	m, diags := r.read(context.Background())
	if diags.HasError() || len(m.UserIDs.Elements()) != 0 || m.Revision.ValueInt64() != 0 || m.UpdatedAt.ValueString() != "" || m.UpdatedBy.ValueString() != "" {
		t.Fatalf("unset: %+v %v", m, diags)
	}
	if _, diags := applyApprovers(r, "user_ana"); diags.HasError() {
		t.Fatal(diags)
	}
	// Someone changes the list outside Terraform.
	api.userIDs, api.revision = []string{"user_ana", "user_other"}, 5
	m, diags = r.read(context.Background())
	if diags.HasError() || !m.UserIDs.Equal(reviewerSet("user_ana", "user_other")) || m.Revision.ValueInt64() != 5 {
		t.Fatalf("drift: %+v %v", m, diags)
	}
}

func TestTenantApproversEmptyListIsSentAndAllowed(t *testing.T) {
	api := newApproversAPI("user_ana")
	r := approversResource(t, api, false)
	if _, diags := applyApprovers(r, "user_ana"); diags.HasError() {
		t.Fatal(diags)
	}
	saved, diags := applyApprovers(r)
	if diags.HasError() {
		t.Fatal(diags)
	}
	if ids, ok := api.bodies[1]["user_ids"].([]any); !ok || len(ids) != 0 {
		t.Fatalf("an empty list is sent as [], not omitted: %v", api.bodies[1])
	}
	if len(saved.UserIDs.Elements()) != 0 || saved.Revision.ValueInt64() != 2 {
		t.Fatalf("state %+v", saved)
	}
}

func TestTenantApproversAPIKeyIsRefusedBeforeAnyRequest(t *testing.T) {
	api := newApproversAPI("user_ana")
	r := approversResource(t, api, true)
	_, diags := applyApprovers(r, "user_ana")
	if !diags.HasError() || !strings.Contains(diags.Errors()[0].Detail(), "use_thothctl_session") {
		t.Fatalf("an API key must be refused with the fix: %v", diags)
	}
	var del resource.DeleteResponse
	r.Delete(context.Background(), resource.DeleteRequest{}, &del)
	if !del.Diagnostics.HasError() || len(api.calls) != 0 {
		t.Fatalf("delete refused too, and nothing was sent: %v %v", del.Diagnostics, api.calls)
	}
}

func TestTenantApproversServerRefusalsReachThePerson(t *testing.T) {
	api := newApproversAPI("user_ana")
	r := approversResource(t, api, false)
	if _, diags := applyApprovers(r, "user_nobody"); !diags.HasError() || !strings.Contains(diags.Errors()[0].Detail(), "verified, active member") {
		t.Fatalf("422: %v", diags)
	}
	api.outage = true
	if _, diags := applyApprovers(r, "user_ana"); !diags.HasError() || !strings.Contains(diags.Errors()[0].Summary(), "could not be verified") {
		t.Fatalf("503: %v", diags)
	}
	// The server, not only the provider, refuses an API key on PUT.
	keyed := approversResource(t, newApproversAPI("user_ana"), true)
	if _, err := keyed.client.SetTenantApprovers(context.Background(), 0, []string{"user_ana"}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("403: %v", err)
	}
}

func TestTenantApproversDeleteSavesAnEmptyList(t *testing.T) {
	api := newApproversAPI("user_ana", "user_bo")
	r := approversResource(t, api, false)
	if _, diags := applyApprovers(r, "user_ana", "user_bo"); diags.HasError() {
		t.Fatal(diags)
	}
	var del resource.DeleteResponse
	r.Delete(context.Background(), resource.DeleteRequest{}, &del)
	if del.Diagnostics.HasError() {
		t.Fatal(del.Diagnostics)
	}
	if len(api.userIDs) != 0 || api.revision != 2 {
		t.Fatalf("destroy empties the list: %v rev %d", api.userIDs, api.revision)
	}
}

func TestTenantApproversImportTakesTheTenantID(t *testing.T) {
	r := approversResource(t, newApproversAPI(), false)
	var ok resource.ImportStateResponse
	ok.State = emptyState(t, r)
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: approversTenant}, &ok)
	if ok.Diagnostics.HasError() {
		t.Fatal(ok.Diagnostics)
	}
	var id types.String
	if diags := ok.State.GetAttribute(context.Background(), path.Root("id"), &id); diags.HasError() || id.ValueString() != approversTenant {
		t.Fatalf("id %v %v", id, diags)
	}
	var bad resource.ImportStateResponse
	bad.State = emptyState(t, r)
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "other"}, &bad)
	if !bad.Diagnostics.HasError() {
		t.Fatal("another tenant ID is refused")
	}
}

func emptyState(t *testing.T, r resource.Resource) tfsdk.State {
	t.Helper()
	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	return tfsdk.State{Schema: resp.Schema, Raw: tftypes.NewValue(resp.Schema.Type().TerraformType(context.Background()), nil)}
}
