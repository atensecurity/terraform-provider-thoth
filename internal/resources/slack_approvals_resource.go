package resources

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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

var _ resource.Resource = &slackApprovalsResource{}
var _ resource.ResourceWithImportState = &slackApprovalsResource{}

type slackApprovalsResource struct {
	client   *client.Client
	tenantID string
}

type slackApprovalsModel struct {
	ID             types.String `tfsdk:"id"`
	ChannelID      types.String `tfsdk:"channel_id"`
	ReviewerEmails types.Set    `tfsdk:"reviewer_emails"`
	SlackTeamID    types.String `tfsdk:"slack_workspace_id"`
	Ready          types.Bool   `tfsdk:"ready"`
}

func NewSlackApprovalsResource() resource.Resource { return &slackApprovalsResource{} }

func (r *slackApprovalsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_slack_approvals"
}

func (r *slackApprovalsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Where held actions are sent for approval in Slack, and who may approve them. Install the Thoth Slack " +
			"app first: that is a browser step in Settings. Reviewers are appointed by a signed-in admin, so the provider " +
			"must use `use_thothctl_session`; API keys are refused. Destroying this resource removes the reviewers and " +
			"leaves the channel and the Slack connection.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "Terraform resource identifier (tenant ID).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"channel_id": schema.StringAttribute{
				Optional: true, Computed: true,
				Description:   "The Slack channel ID (such as C0123456789) held actions are posted to. Unset keeps the current channel.",
				Validators:    []validator.String{stringvalidator.RegexMatches(slackChannelIDPattern, "must be a Slack channel ID, such as C0123456789")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"reviewer_emails": schema.SetAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "Who may approve held actions in Slack, at most 50. Each must be a verified, active member of the organization. An empty set allows no one.",
				Validators:  []validator.Set{setvalidator.SizeAtMost(50), setvalidator.ValueStringsAre(plainEmailValidator{})},
			},
			"slack_workspace_id": schema.StringAttribute{Computed: true, Description: "The connected Slack workspace."},
			"ready":              schema.BoolAttribute{Computed: true, Description: "Whether Slack approvals are ready: a channel and at least one reviewer who can act."},
		},
	}
}

var slackChannelIDPattern = regexp.MustCompile(`^[CG][A-Z0-9]{1,31}$`)

func (r *slackApprovalsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *slackApprovalsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.apply(ctx, req.Plan.Get, func(m slackApprovalsModel) diag.Diagnostics { return resp.State.Set(ctx, &m) }, &resp.Diagnostics)
}

func (r *slackApprovalsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.apply(ctx, req.Plan.Get, func(m slackApprovalsModel) diag.Diagnostics { return resp.State.Set(ctx, &m) }, &resp.Diagnostics)
}

func (r *slackApprovalsResource) apply(ctx context.Context, get func(context.Context, any) diag.Diagnostics, save func(slackApprovalsModel) diag.Diagnostics, diags *diag.Diagnostics) {
	var plan slackApprovalsModel
	diags.Append(get(ctx, &plan)...)
	if diags.HasError() || !requirePerson(r.client, diags) {
		return
	}
	status, err := r.client.SlackStatus(ctx)
	if err != nil {
		diags.AddError("Error reading the Slack connection", err.Error())
		return
	}
	workspace := tfhelpers.GetString(tfhelpers.GetMap(status, "workspace"), "id")
	if workspace == "" {
		diags.AddError("Slack is not connected", "Install the Thoth Slack app in Settings first; that is a browser step.")
		return
	}
	if knownString(plan.ChannelID) && plan.ChannelID.ValueString() != tfhelpers.GetString(tfhelpers.GetMap(status, "notification_channel"), "id") {
		if err := r.client.SetSlackChannel(ctx, plan.ChannelID.ValueString()); err != nil {
			diags.AddError("Error setting the Slack approvals channel", err.Error())
			return
		}
	}
	var emails []string
	diags.Append(plan.ReviewerEmails.ElementsAs(ctx, &emails, false)...)
	if diags.HasError() {
		return
	}
	ids, err := r.reviewerIDs(ctx, emails)
	if err != nil {
		diags.AddAttributeError(path.Root("reviewer_emails"), "Cannot appoint these reviewers", err.Error())
		return
	}
	if err := r.setReviewers(ctx, workspace, ids); err != nil {
		diags.AddError("Error setting Slack reviewers", err.Error())
		return
	}
	next, d := r.read(ctx)
	diags.Append(d...)
	if !diags.HasError() {
		diags.Append(save(next)...)
	}
}

// reviewerIDs resolves emails to the verified members GovAPI accepts.
func (r *slackApprovalsResource) reviewerIDs(ctx context.Context, emails []string) ([]string, error) {
	if len(emails) == 0 {
		return []string{}, nil
	}
	candidates, err := r.client.SlackReviewerCandidates(ctx)
	if err != nil {
		return nil, err
	}
	byEmail := map[string]string{}
	for _, c := range candidates {
		byEmail[strings.ToLower(tfhelpers.GetString(c, "email"))] = tfhelpers.GetString(c, "workos_user_id")
	}
	ids := make([]string, 0, len(emails))
	var missing []string
	for _, email := range emails {
		if id := byEmail[strings.ToLower(email)]; id != "" {
			ids = append(ids, id)
		} else {
			missing = append(missing, email)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("not verified, active members of this organization: %s", strings.Join(missing, ", "))
	}
	return ids, nil
}

func (r *slackApprovalsResource) setReviewers(ctx context.Context, workspace string, ids []string) error {
	current, err := r.client.SlackReviewers(ctx)
	if err != nil {
		return err
	}
	return r.client.SetSlackReviewers(ctx, workspace, tfhelpers.GetString(current, "revision"), ids)
}

// read reports the channel, the reviewers by email and readiness.
func (r *slackApprovalsResource) read(ctx context.Context) (slackApprovalsModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	m := slackApprovalsModel{ID: types.StringValue(r.tenantID)}
	status, err := r.client.SlackStatus(ctx)
	if err != nil {
		diags.AddError("Error reading the Slack connection", err.Error())
		return m, diags
	}
	m.SlackTeamID = stringValueFromMap(tfhelpers.GetMap(status, "workspace"), "id")
	m.ChannelID = stringValueFromMap(tfhelpers.GetMap(status, "notification_channel"), "id")
	reviewers, err := r.client.SlackReviewers(ctx)
	if err != nil {
		diags.AddError("Error reading Slack reviewers", err.Error())
		return m, diags
	}
	m.Ready = types.BoolValue(tfhelpers.GetBool(reviewers, "ready"))
	candidates, err := r.client.SlackReviewerCandidates(ctx)
	if err != nil {
		diags.AddError("Error reading Slack reviewer candidates", err.Error())
		return m, diags
	}
	emailByID := map[string]string{}
	for _, c := range candidates {
		emailByID[tfhelpers.GetString(c, "workos_user_id")] = strings.ToLower(tfhelpers.GetString(c, "email"))
	}
	var emails []string
	for _, rv := range objectsAt(reviewers, "reviewers") {
		id := tfhelpers.GetString(rv, "workos_user_id")
		if email := emailByID[id]; email != "" {
			emails = append(emails, email)
		} else {
			// A reviewer who is no longer a verified member still shows, by ID,
			// so the plan removes them.
			emails = append(emails, id)
		}
	}
	sort.Strings(emails)
	values := make([]attr.Value, 0, len(emails))
	for _, e := range emails {
		values = append(values, types.StringValue(e))
	}
	set, d := types.SetValue(types.StringType, values)
	diags.Append(d...)
	m.ReviewerEmails = set
	return m, diags
}

func objectsAt(m map[string]any, key string) []map[string]any {
	items, _ := m[key].([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if obj, ok := item.(map[string]any); ok {
			out = append(out, obj)
		}
	}
	return out
}

func (r *slackApprovalsResource) Read(ctx context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	next, diags := r.read(ctx)
	resp.Diagnostics.Append(diags...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
	}
}

// Delete removes the reviewers; the channel and the Slack connection stay.
func (r *slackApprovalsResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !requirePerson(r.client, &resp.Diagnostics) {
		return
	}
	status, err := r.client.SlackStatus(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading the Slack connection", err.Error())
		return
	}
	workspace := tfhelpers.GetString(tfhelpers.GetMap(status, "workspace"), "id")
	if workspace == "" {
		return
	}
	if err := r.setReviewers(ctx, workspace, []string{}); err != nil {
		resp.Diagnostics.AddError("Error removing Slack reviewers", err.Error())
	}
}

func (r *slackApprovalsResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), r.tenantID)...)
}
