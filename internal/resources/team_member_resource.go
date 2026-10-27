package resources

import (
	"context"
	"fmt"
	"net/mail"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &teamMemberResource{}
var _ resource.ResourceWithImportState = &teamMemberResource{}
var _ resource.ResourceWithValidateConfig = &teamMemberResource{}

type teamMemberResource struct {
	client *client.Client
}

type teamMemberModel struct {
	ID     types.String `tfsdk:"id"`
	Email  types.String `tfsdk:"email"`
	Role   types.String `tfsdk:"role"`
	Status types.String `tfsdk:"status"`
	UserID types.String `tfsdk:"user_id"`
}

func NewTeamMemberResource() resource.Resource { return &teamMemberResource{} }

func (r *teamMemberResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_team_member"
}

func (r *teamMemberResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "One person in the workspace and their role. Creating it invites them; destroying it removes them, " +
			"or revokes their invitation. People are managed by a signed-in admin, so the provider must use " +
			"`use_thothctl_session`; API keys are refused. GovAPI keeps at least one admin.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "The person's email.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"email": schema.StringAttribute{
				Required: true, Description: "The person's email address.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{plainEmailValidator{}},
			},
			"role": schema.StringAttribute{
				Required: true,
				Description: "admin, or viewer on self-serve and trial workspaces and member on dedicated ones. On self-serve " +
					"and trial workspaces invitees join as viewers, and a role other than viewer is applied by the first " +
					"apply after they join.",
			},
			"status": schema.StringAttribute{Computed: true, Description: "invited, or the membership status (active once they join)."},
			"user_id": schema.StringAttribute{
				Computed: true, Description: "The person's user ID once they have joined.",
			},
		},
	}
}

func (r *teamMemberResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
}

// ValidateConfig checks the role against the workspace type when the client
// is known (it is not during early validation).
func (r *teamMemberResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg teamMemberModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if cfg.Role.IsUnknown() || cfg.Role.IsNull() {
		return
	}
	switch cfg.Role.ValueString() {
	case "admin", "viewer", "member":
	default:
		resp.Diagnostics.AddAttributeError(path.Root("role"), "Unknown role", "role must be admin, viewer (self-serve and trial) or member (dedicated).")
	}
}

// requirePerson refuses API-key runs: GovAPI only lets a signed-in admin
// change people.
func requirePerson(c *client.Client, diags *diag.Diagnostics) bool {
	if c.IsSignedInUser() {
		return true
	}
	diags.AddError("Needs a signed-in admin",
		"People and Slack reviewers are changed by a signed-in admin, not an API key. Run `thothctl auth login`, "+
			"set use_thothctl_session = true in the provider, and apply again.")
	return false
}

func (r *teamMemberResource) checkRole(role string, diags *diag.Diagnostics) bool {
	shared := r.client.SharedWorkspace()
	if role == "admin" || (shared && role == "viewer") || (!shared && role == "member") {
		return true
	}
	if shared {
		diags.AddAttributeError(path.Root("role"), "Role not used here", "Self-serve and trial workspaces use admin and viewer.")
	} else {
		diags.AddAttributeError(path.Root("role"), "Role not used here", "Dedicated workspaces use admin and member.")
	}
	return false
}

// teamLookup finds the person among members and, on shared workspaces,
// pending invitations.
type teamLookup struct {
	member     map[string]any
	invitation map[string]any
}

func (r *teamMemberResource) lookup(ctx context.Context, email string) (teamLookup, error) {
	var out teamLookup
	members, err := r.client.TeamMembers(ctx)
	if err != nil {
		return out, err
	}
	for _, m := range members {
		if strings.EqualFold(tfhelpers.GetString(m, "email"), email) {
			out.member = m
			return out, nil
		}
	}
	if r.client.SharedWorkspace() {
		invitations, err := r.client.TrialInvitations(ctx)
		if err != nil {
			return out, err
		}
		for _, inv := range invitations {
			if strings.EqualFold(tfhelpers.GetString(inv, "email"), email) {
				out.invitation = inv
			}
		}
	}
	return out, nil
}

func (r *teamMemberResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan teamMemberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !requirePerson(r.client, &resp.Diagnostics) || !r.checkRole(plan.Role.ValueString(), &resp.Diagnostics) {
		return
	}
	email := strings.ToLower(plan.Email.ValueString())
	found, err := r.lookup(ctx, email)
	if err != nil {
		resp.Diagnostics.AddError("Error reading team members", err.Error())
		return
	}
	switch {
	case found.member != nil:
		// Already a member: adopt them and set the role.
		if tfhelpers.GetString(found.member, "role") != plan.Role.ValueString() {
			if err := r.client.SetTeamMemberRole(ctx, email, tfhelpers.GetString(found.member, "user_id"), plan.Role.ValueString()); err != nil {
				resp.Diagnostics.AddError("Error setting the member's role", err.Error())
				return
			}
		}
	case found.invitation != nil:
		// Already invited: nothing to send again.
	default:
		if err := r.client.InviteTeamMember(ctx, email, plan.Role.ValueString()); err != nil {
			resp.Diagnostics.AddError("Error inviting team member", err.Error())
			return
		}
	}
	r.readInto(ctx, &plan, true, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// readInto refreshes status, user_id and role. invited reports whether the
// previous state was an invitation, which dedicated workspaces cannot list:
// such a person is kept as invited until they appear as a member.
func (r *teamMemberResource) readInto(ctx context.Context, m *teamMemberModel, invited bool, diags *diag.Diagnostics) bool {
	email := strings.ToLower(m.Email.ValueString())
	m.ID, m.Email = types.StringValue(email), types.StringValue(email)
	found, err := r.lookup(ctx, email)
	if err != nil {
		diags.AddError("Error reading team members", err.Error())
		return true
	}
	switch {
	case found.member != nil:
		m.Status = types.StringValue(firstNonEmpty(tfhelpers.GetString(found.member, "status"), "active"))
		m.Role = types.StringValue(tfhelpers.GetString(found.member, "role"))
		m.UserID = stringValueFromMap(found.member, "user_id")
		return true
	case found.invitation != nil, invited && !r.client.SharedWorkspace():
		// Until they join, the configured role stands: it is applied then.
		m.Status, m.UserID = types.StringValue("invited"), types.StringNull()
		return true
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (r *teamMemberResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state teamMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.readInto(ctx, &state, state.Status.ValueString() == "invited", &resp.Diagnostics) {
		// They left or the invitation was revoked elsewhere: plan to invite again.
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *teamMemberResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state teamMemberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requirePerson(r.client, &resp.Diagnostics) || !r.checkRole(plan.Role.ValueString(), &resp.Diagnostics) {
		return
	}
	email := strings.ToLower(plan.Email.ValueString())
	found, err := r.lookup(ctx, email)
	if err != nil {
		resp.Diagnostics.AddError("Error reading team members", err.Error())
		return
	}
	if found.member == nil {
		resp.Diagnostics.AddWarning("Role applied after they join",
			fmt.Sprintf("%s has not joined yet. The role is applied by the first apply after they do.", email))
	} else if tfhelpers.GetString(found.member, "role") != plan.Role.ValueString() {
		if err := r.client.SetTeamMemberRole(ctx, email, tfhelpers.GetString(found.member, "user_id"), plan.Role.ValueString()); err != nil {
			resp.Diagnostics.AddError("Error setting the member's role", err.Error())
			return
		}
	}
	r.readInto(ctx, &plan, state.Status.ValueString() == "invited", &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *teamMemberResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state teamMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requirePerson(r.client, &resp.Diagnostics) {
		return
	}
	email := strings.ToLower(state.Email.ValueString())
	found, err := r.lookup(ctx, email)
	if err != nil {
		resp.Diagnostics.AddError("Error reading team members", err.Error())
		return
	}
	switch {
	case found.member != nil:
		if err := r.client.RemoveTeamMember(ctx, email, tfhelpers.GetString(found.member, "user_id")); err != nil && !client.IsNotFound(err) {
			resp.Diagnostics.AddError("Error removing team member", err.Error())
		}
	case found.invitation != nil:
		if err := r.client.RevokeTrialInvitation(ctx, tfhelpers.GetString(found.invitation, "id")); err != nil && !client.IsNotFound(err) {
			resp.Diagnostics.AddError("Error revoking the invitation", err.Error())
		}
	case state.Status.ValueString() == "invited" && !r.client.SharedWorkspace():
		resp.Diagnostics.AddWarning("Invitation not revoked",
			"Dedicated workspaces invite through your identity provider; revoke the pending invitation there.")
	}
}

func (r *teamMemberResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	email := strings.ToLower(strings.TrimSpace(req.ID))
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("email"), email)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), email)...)
}

// plainEmailValidator accepts one plain address, as GovAPI does.
type plainEmailValidator struct{}

func (plainEmailValidator) Description(context.Context) string { return "a plain email address" }
func (v plainEmailValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (plainEmailValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()
	addr, err := mail.ParseAddress(value)
	if err != nil || addr.Name != "" || addr.Address != strings.TrimSpace(value) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid email", fmt.Sprintf("%q is not a plain email address.", value))
	}
}
