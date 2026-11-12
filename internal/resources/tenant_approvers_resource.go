package resources

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sort"

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

var _ resource.Resource = &tenantApproversResource{}
var _ resource.ResourceWithImportState = &tenantApproversResource{}

type tenantApproversResource struct {
	client   *client.Client
	tenantID string
}

type tenantApproversModel struct {
	ID        types.String `tfsdk:"id"`
	UserIDs   types.Set    `tfsdk:"user_ids"`
	Revision  types.Int64  `tfsdk:"revision"`
	UpdatedBy types.String `tfsdk:"updated_by"`
	UpdatedAt types.String `tfsdk:"updated_at"`
}

// workosUserIDPattern is the user ID shape GovAPI accepts for an approver.
var workosUserIDPattern = regexp.MustCompile(`^user_[A-Za-z0-9]{1,80}$`)

func NewTenantApproversResource() resource.Resource { return &tenantApproversResource{} }

func (r *tenantApproversResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant_approvers"
}

func (r *tenantApproversResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Who may approve held actions on a workspace that has no Slack workspace connected, such as a dedicated " +
			"deployment. The list is explicit: an empty list means nobody can approve, and there is no all-admins mode. " +
			"The list is chosen by a signed-in organization admin with recent MFA, so the provider must use " +
			"`use_thothctl_session` (or an admin bearer token); API keys are refused. Destroying this resource " +
			"saves an EMPTY list: nobody can approve a held action until a new list is set.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "Terraform resource identifier (tenant ID).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"user_ids": schema.SetAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "WorkOS user IDs (such as user_01H...) of the people who may approve held actions, at most 50. Each must be a verified, active member of the organization. An empty set allows no one.",
				Validators: []validator.Set{setvalidator.SizeAtMost(50), setvalidator.ValueStringsAre(
					stringvalidator.RegexMatches(workosUserIDPattern, "must be a WorkOS user ID, such as user_01H..."))},
			},
			"revision":   schema.Int64Attribute{Computed: true, Description: "How many times the list has been saved. A save names the revision it read, so a change made at the same time elsewhere is refused rather than overwritten."},
			"updated_by": schema.StringAttribute{Computed: true, Description: "The user ID of the admin who last saved the list. Empty until the list is first saved."},
			"updated_at": schema.StringAttribute{Computed: true, Description: "When the list was last saved (RFC 3339). Empty until the list is first saved."},
		},
	}
}

func (r *tenantApproversResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *tenantApproversResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.apply(ctx, req.Plan.Get, func(m tenantApproversModel) diag.Diagnostics { return resp.State.Set(ctx, &m) }, &resp.Diagnostics)
}

func (r *tenantApproversResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.apply(ctx, req.Plan.Get, func(m tenantApproversModel) diag.Diagnostics { return resp.State.Set(ctx, &m) }, &resp.Diagnostics)
}

func (r *tenantApproversResource) apply(ctx context.Context, get func(context.Context, any) diag.Diagnostics, save func(tenantApproversModel) diag.Diagnostics, diags *diag.Diagnostics) {
	var plan tenantApproversModel
	diags.Append(get(ctx, &plan)...)
	if diags.HasError() || !requirePerson(r.client, diags) {
		return
	}
	var ids []string
	diags.Append(plan.UserIDs.ElementsAs(ctx, &ids, false)...)
	if diags.HasError() {
		return
	}
	sort.Strings(ids)
	if !r.replace(ctx, ids, diags) {
		return
	}
	next, d := r.read(ctx)
	diags.Append(d...)
	if !diags.HasError() {
		diags.Append(save(next)...)
	}
}

// replace reads the current revision, then saves the whole list against it.
func (r *tenantApproversResource) replace(ctx context.Context, ids []string, diags *diag.Diagnostics) bool {
	current, err := r.client.TenantApprovers(ctx)
	if err != nil {
		diags.AddError("Error reading the approvers", err.Error())
		return false
	}
	if _, err := r.client.SetTenantApprovers(ctx, tfhelpers.GetInt64(current, "revision"), ids); err != nil {
		var apiErr *client.APIError
		switch {
		case errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict:
			diags.AddError("The approvers changed while this apply ran",
				"Someone else saved the approver list after it was read, so nothing was overwritten. Run the plan again to see the current list.")
		case errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusServiceUnavailable:
			diags.AddError("Approvers could not be verified",
				"Thoth could not check organization membership with its identity provider, so the list was not changed. Apply again shortly. "+err.Error())
		case errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnprocessableEntity:
			diags.AddAttributeError(path.Root("user_ids"), "Cannot appoint these approvers",
				"Each must be a verified, active member of the organization. "+err.Error())
		default:
			diags.AddError("Error setting the approvers", err.Error())
		}
		return false
	}
	return true
}

func (r *tenantApproversResource) read(ctx context.Context) (tenantApproversModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	m := tenantApproversModel{ID: types.StringValue(r.tenantID)}
	current, err := r.client.TenantApprovers(ctx)
	if err != nil {
		diags.AddError("Error reading the approvers", err.Error())
		return m, diags
	}
	ids := tfhelpers.GetStringSlice(current, "user_ids")
	sort.Strings(ids)
	values := make([]attr.Value, 0, len(ids))
	for _, id := range ids {
		values = append(values, types.StringValue(id))
	}
	set, d := types.SetValue(types.StringType, values)
	diags.Append(d...)
	m.UserIDs = set
	m.Revision = types.Int64Value(tfhelpers.GetInt64(current, "revision"))
	m.UpdatedBy = types.StringValue(tfhelpers.GetString(current, "updated_by"))
	m.UpdatedAt = types.StringValue(tfhelpers.GetString(current, "updated_at"))
	return m, diags
}

func (r *tenantApproversResource) Read(ctx context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	next, diags := r.read(ctx)
	resp.Diagnostics.Append(diags...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
	}
}

// Delete saves an empty list, which means nobody can approve a held action.
// It follows thoth_slack_approvals, whose destroy removes the reviewers: a
// destroy that left the old list in force would let people stay approvers
// after the configuration that named them is gone.
func (r *tenantApproversResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !requirePerson(r.client, &resp.Diagnostics) {
		return
	}
	r.replace(ctx, []string{}, &resp.Diagnostics)
}

func (r *tenantApproversResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID != r.tenantID {
		resp.Diagnostics.AddError("Import ID must be the tenant ID", "Use the tenant ID the provider is configured with: "+r.tenantID)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), r.tenantID)...)
}
