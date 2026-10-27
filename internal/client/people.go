package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
)

// People and Slack approvers. GovAPI accepts these only from a signed-in
// admin (IsSignedInUser), never an API key.
//
// Self-serve and trial workspaces (a 32-character workspace ID) keep members
// on the workspace record: /thoth/trial-members and /thoth/trial-invitations,
// roles admin and viewer, invitees joining as viewers. Dedicated workspaces
// use the WorkOS organization: /team/members and /team/invitations, roles
// admin and member.

var sharedWorkspaceID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// SharedWorkspace reports whether the tenant is a self-serve or trial workspace.
func (c *Client) SharedWorkspace() bool { return sharedWorkspaceID.MatchString(c.tenantID) }

func (c *Client) teamPath(path string) string { return fmt.Sprintf("/%s/team/%s", c.tenantID, path) }

// TeamMembers lists members: email, role and status, plus user_id on
// dedicated workspaces.
func (c *Client) TeamMembers(ctx context.Context) ([]map[string]any, error) {
	var out struct {
		Members []map[string]any `json:"members"`
	}
	path := c.teamPath("members")
	if c.SharedWorkspace() {
		path = c.tenantPath("trial-members")
	}
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true)
	return out.Members, err
}

// TrialInvitations lists pending invitations on a shared workspace.
func (c *Client) TrialInvitations(ctx context.Context) ([]map[string]any, error) {
	var out struct {
		Invitations []map[string]any `json:"invitations"`
	}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("trial-invitations"), nil, nil, &out, true)
	return out.Invitations, err
}

// InviteTeamMember invites one person. Shared workspaces take no role: the
// invitee joins as a viewer.
func (c *Client) InviteTeamMember(ctx context.Context, email, role string) error {
	if c.SharedWorkspace() {
		return c.doJSON(ctx, http.MethodPost, c.tenantPath("trial-invitations"), nil, map[string]any{"email": email}, nil, false)
	}
	return c.doJSON(ctx, http.MethodPost, c.teamPath("invitations"), nil, map[string]any{"email": email, "role": role}, nil, false)
}

// SetTeamMemberRole changes a member's role. userID is used on dedicated
// workspaces, email on shared ones.
func (c *Client) SetTeamMemberRole(ctx context.Context, email, userID, role string) error {
	body := map[string]any{"role": role}
	if c.SharedWorkspace() {
		return c.doJSON(ctx, http.MethodPut, c.tenantPath("trial-members/"+url.PathEscape(email)+"/role"), nil, body, nil, false)
	}
	return c.doJSON(ctx, http.MethodPut, c.teamPath("members/"+url.PathEscape(userID)+"/role"), nil, body, nil, false)
}

func (c *Client) RemoveTeamMember(ctx context.Context, email, userID string) error {
	if c.SharedWorkspace() {
		return c.doJSON(ctx, http.MethodDelete, c.tenantPath("trial-members/"+url.PathEscape(email)), nil, nil, nil, false)
	}
	return c.doJSON(ctx, http.MethodDelete, c.teamPath("members/"+url.PathEscape(userID)), nil, nil, nil, false)
}

func (c *Client) RevokeTrialInvitation(ctx context.Context, invitationID string) error {
	return c.doJSON(ctx, http.MethodDelete, c.tenantPath("trial-invitations/"+url.PathEscape(invitationID)), nil, nil, nil, false)
}

// SlackStatus is the connected Slack workspace and its approvals channel.
func (c *Client) SlackStatus(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("integrations/slack"), nil, nil, &out, true)
	return out, err
}

func (c *Client) SetSlackChannel(ctx context.Context, channelID string) error {
	return c.doJSON(ctx, http.MethodPut, c.tenantPath("integrations/slack/channel"), nil, map[string]any{"channel_id": channelID}, nil, false)
}

// SlackReviewers is the reviewer configuration: revision, reviewers, ready.
func (c *Client) SlackReviewers(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.doJSON(ctx, http.MethodGet, c.tenantPath("integrations/slack/reviewers"), nil, nil, &out, true)
	return out, err
}

// SlackReviewerCandidates lists verified members who can review, with email
// and workos_user_id.
func (c *Client) SlackReviewerCandidates(ctx context.Context) ([]map[string]any, error) {
	var all []map[string]any
	after := ""
	for page := 0; page < 50; page++ { // at most 50 pages; the API pages members
		var query map[string]string
		if after != "" {
			query = map[string]string{"after": after}
		}
		var raw map[string]any
		if err := c.doJSON(ctx, http.MethodGet, c.tenantPath("integrations/slack/reviewers/candidates"), query, nil, &raw, true); err != nil {
			return nil, err
		}
		all = append(all, objectList(raw, "candidates")...)
		next, _ := raw["next_cursor"].(string)
		if next == "" || next == after {
			return all, nil
		}
		after = next
	}
	return all, nil
}

// SetSlackReviewers replaces the reviewers. revision is the one last read, so
// a concurrent change refuses this one instead of being overwritten.
func (c *Client) SetSlackReviewers(ctx context.Context, workspaceID, revision string, userIDs []string) error {
	if userIDs == nil {
		userIDs = []string{}
	}
	body := map[string]any{"workspace_id": workspaceID, "revision": revision, "workos_user_ids": userIDs}
	return c.doJSON(ctx, http.MethodPut, c.tenantPath("integrations/slack/reviewers"), nil, body, nil, false)
}

// objectList accepts a bare array or an object holding one under key.
func objectList(raw any, key string) []map[string]any {
	items, ok := raw.([]any)
	if !ok {
		if wrapped, isMap := raw.(map[string]any); isMap {
			items, _ = wrapped[key].([]any)
		}
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
