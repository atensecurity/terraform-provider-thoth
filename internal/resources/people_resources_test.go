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
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

const sharedTenant = "0123456789abcdef0123456789abcdef"

// peopleAPI fakes the member, invitation and Slack routes.
type peopleAPI struct {
	mu          sync.Mutex
	members     []map[string]any
	invitations []map[string]any
	calls       []string
	reviewers   []string
	revision    string
	putBody     map[string]any
}

func (a *peopleAPI) handler(t *testing.T, tenant string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		rest := strings.TrimPrefix(r.URL.Path, "/"+tenant)
		body := map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		a.calls = append(a.calls, r.Method+" "+rest)
		reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		switch {
		case r.Method == http.MethodGet && (rest == "/thoth/trial-members" || rest == "/team/members"):
			reply(map[string]any{"members": a.members})
		case r.Method == http.MethodGet && rest == "/thoth/trial-invitations":
			reply(map[string]any{"invitations": a.invitations})
		case r.Method == http.MethodPost && rest == "/thoth/trial-invitations":
			a.invitations = append(a.invitations, map[string]any{"id": "inv_1", "email": body["email"]})
			reply(map[string]any{})
		case r.Method == http.MethodGet && rest == "/thoth/integrations/slack":
			reply(map[string]any{"workspace": map[string]any{"id": "T0123"}, "notification_channel": map[string]any{"id": "C0001"}})
		case r.Method == http.MethodGet && rest == "/thoth/integrations/slack/reviewers/candidates":
			if r.URL.Query().Get("after") == "" {
				reply(map[string]any{"candidates": []any{map[string]any{"email": "Ana@acme.example", "workos_user_id": "user_ana"}}, "next_cursor": "page2"})
				return
			}
			reply(map[string]any{"candidates": []any{map[string]any{"email": "bo@acme.example", "workos_user_id": "user_bo"}}})
		case r.Method == http.MethodGet && rest == "/thoth/integrations/slack/reviewers":
			list := []any{}
			for _, id := range a.reviewers {
				list = append(list, map[string]any{"workos_user_id": id})
			}
			reply(map[string]any{"revision": a.revision, "reviewers": list, "ready": len(a.reviewers) > 0})
		case r.Method == http.MethodPut && rest == "/thoth/integrations/slack/reviewers":
			a.putBody = body
			a.reviewers = nil
			for _, id := range body["workos_user_ids"].([]any) {
				a.reviewers = append(a.reviewers, id.(string))
			}
			reply(map[string]any{})
		default:
			reply(map[string]any{})
		}
	})
}

func peopleClient(t *testing.T, api *peopleAPI, tenant string, apiKey bool) *client.Client {
	t.Helper()
	server := httptest.NewServer(api.handler(t, tenant))
	t.Cleanup(server.Close)
	cfg := client.Config{BaseURL: server.URL, TenantID: tenant, AuthToken: "user-token"}
	if apiKey {
		cfg = client.Config{BaseURL: server.URL, TenantID: tenant, APIKey: "key"}
	}
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPeopleResourcesRefuseAPIKeys(t *testing.T) {
	var diags diag.Diagnostics
	if requirePerson(peopleClient(t, &peopleAPI{}, sharedTenant, true), &diags) || !strings.Contains(diags.Errors()[0].Detail(), "use_thothctl_session") {
		t.Fatalf("an API key must be refused with the fix: %v", diags)
	}
	if !requirePerson(peopleClient(t, &peopleAPI{}, sharedTenant, false), &diag.Diagnostics{}) {
		t.Fatal("a signed-in session is allowed")
	}
}

func TestTeamMemberRolesFollowTheWorkspaceType(t *testing.T) {
	shared := &teamMemberResource{client: peopleClient(t, &peopleAPI{}, sharedTenant, false)}
	dedicated := &teamMemberResource{client: peopleClient(t, &peopleAPI{}, "acme", false)}
	for _, tc := range []struct {
		r    *teamMemberResource
		role string
		ok   bool
	}{{shared, "viewer", true}, {shared, "member", false}, {dedicated, "member", true}, {dedicated, "viewer", false}, {shared, "admin", true}, {dedicated, "admin", true}} {
		var diags diag.Diagnostics
		if tc.r.checkRole(tc.role, &diags) != tc.ok {
			t.Errorf("shared=%v role=%s: %v", tc.r.client.SharedWorkspace(), tc.role, diags)
		}
	}
}

func TestTeamMemberInvitationKeepsTheConfiguredRoleUntilTheyJoin(t *testing.T) {
	api := &peopleAPI{}
	r := &teamMemberResource{client: peopleClient(t, api, sharedTenant, false)}
	ctx := context.Background()
	if err := r.client.InviteTeamMember(ctx, "dana@acme.example", "admin"); err != nil {
		t.Fatal(err)
	}
	m := teamMemberModel{Email: types.StringValue("Dana@acme.example"), Role: types.StringValue("admin")}
	var diags diag.Diagnostics
	if !r.readInto(ctx, &m, false, &diags) || m.Status.ValueString() != "invited" || m.Role.ValueString() != "admin" {
		t.Fatalf("invited: %+v %v", m, diags)
	}
	// They joined as a viewer: the next plan shows the role to apply.
	api.invitations = nil
	api.members = []map[string]any{{"email": "dana@acme.example", "role": "viewer", "status": "active"}}
	if !r.readInto(ctx, &m, true, &diags) || m.Status.ValueString() != "active" || m.Role.ValueString() != "viewer" {
		t.Fatalf("joined: %+v", m)
	}
	// Gone from both: removed from state, so the next plan invites again.
	api.members = nil
	if r.readInto(ctx, &m, false, &diags) {
		t.Fatal("a person no longer in the workspace is not found")
	}
}

func TestTeamMemberDedicatedInvitationsAreKeptUntilTheyJoin(t *testing.T) {
	r := &teamMemberResource{client: peopleClient(t, &peopleAPI{}, "acme", false)}
	m := teamMemberModel{Email: types.StringValue("eve@acme.example"), Role: types.StringValue("member"), Status: types.StringValue("invited")}
	var diags diag.Diagnostics
	// WorkOS invitations are not listed; a pending invite stays in state.
	if !r.readInto(context.Background(), &m, true, &diags) || m.Status.ValueString() != "invited" {
		t.Fatalf("%+v", m)
	}
}

func reviewerSet(emails ...string) types.Set {
	values := make([]attr.Value, 0, len(emails))
	for _, e := range emails {
		values = append(values, types.StringValue(e))
	}
	return types.SetValueMust(types.StringType, values)
}

func TestSlackApprovalsResolvesReviewersAcrossPages(t *testing.T) {
	api := &peopleAPI{revision: "rev-1"}
	r := &slackApprovalsResource{client: peopleClient(t, api, sharedTenant, false), tenantID: sharedTenant}
	ctx := context.Background()
	plan := slackApprovalsModel{ChannelID: types.StringValue("C0001"), ReviewerEmails: reviewerSet("ana@acme.example", "bo@acme.example")}
	var saved slackApprovalsModel
	var diags diag.Diagnostics
	r.apply(ctx, func(_ context.Context, target any) diag.Diagnostics {
		*(target.(*slackApprovalsModel)) = plan
		return nil
	}, func(m slackApprovalsModel) diag.Diagnostics { saved = m; return nil }, &diags)
	if diags.HasError() {
		t.Fatalf("apply: %v", diags)
	}
	if api.putBody["revision"] != "rev-1" || api.putBody["workspace_id"] != "T0123" {
		t.Fatalf("the revision read is sent back: %v", api.putBody)
	}
	for _, call := range api.calls {
		if strings.HasPrefix(call, "PUT /thoth/integrations/slack/channel") {
			t.Fatal("an unchanged channel is not set again")
		}
	}
	if !saved.Ready.ValueBool() || !saved.ReviewerEmails.Equal(reviewerSet("ana@acme.example", "bo@acme.example")) {
		t.Fatalf("state %+v", saved)
	}

	// An email that is not a verified member is refused by name.
	var refused diag.Diagnostics
	if _, err := r.reviewerIDs(ctx, []string{"ana@acme.example", "mallory@evil.example"}); err == nil || !strings.Contains(err.Error(), "mallory@evil.example") {
		t.Fatalf("err %v %v", err, refused)
	}
}

func TestSlackApprovalsShowsDepartedReviewersByID(t *testing.T) {
	api := &peopleAPI{revision: "rev-1", reviewers: []string{"user_ana", "user_gone"}}
	r := &slackApprovalsResource{client: peopleClient(t, api, sharedTenant, false), tenantID: sharedTenant}
	m, diags := r.read(context.Background())
	if diags.HasError() {
		t.Fatal(diags)
	}
	if !m.ReviewerEmails.Equal(reviewerSet("ana@acme.example", "user_gone")) {
		t.Fatalf("reviewers %v", m.ReviewerEmails)
	}
}
