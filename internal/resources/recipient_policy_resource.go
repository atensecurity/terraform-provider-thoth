package resources

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

// Thoth's behavior for a workspace that has not chosen: observe, with the sign-in domains as internal.
const recipientPolicyDefaultMode = "observe"

// Lowercase, no leading "@" or trailing dot: the form Thoth stores, so a plan never differs from the result.
var (
	recipientDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)
	recipientNamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)
)

var _ resource.Resource = &recipientPolicyResource{}
var _ resource.ResourceWithImportState = &recipientPolicyResource{}

type recipientPolicyResource struct {
	client   *client.Client
	tenantID string
}

type recipientPolicyModel struct {
	ID                     types.String `tfsdk:"id"`
	TenantID               types.String `tfsdk:"tenant_id"`
	Mode                   types.String `tfsdk:"mode"`
	InternalDomains        types.List   `tfsdk:"internal_domains"`
	AllowedExternalDomains types.List   `tfsdk:"allowed_external_domains"`
	AllowedDestinations    types.List   `tfsdk:"allowed_destinations"`
	InternalDomainsSource  types.String `tfsdk:"internal_domains_source"`
}

func NewRecipientPolicyResource() resource.Resource {
	return &recipientPolicyResource{}
}

func (r *recipientPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_recipient_policy"
}

func recipientEmptyList() types.List {
	return types.ListValueMust(types.StringType, []attr.Value{})
}

func recipientDomainList(description string) schema.ListAttribute {
	return schema.ListAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Computed:    true,
		Default:     listdefault.StaticValue(recipientEmptyList()),
		Description: description,
		Validators: []validator.List{
			listvalidator.SizeAtMost(200),
			listvalidator.UniqueValues(),
			listvalidator.ValueStringsAre(stringvalidator.RegexMatches(recipientDomainPattern, "must be a lowercase domain such as partner.example")),
		},
	}
}

func (r *recipientPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The outside-recipient guard: whether sends, shares and invitations an agent addresses outside " +
			"the workspace step up for a person's approval. Forwards, shares and exports step up for any address " +
			"outside `internal_domains`; plain sends also accept `allowed_external_domains`. A recipient that is not " +
			"an address steps up unless it is in `allowed_destinations`. Destroying this resource returns the " +
			"workspace to the defaults: `observe`, with its sign-in domains as internal.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Terraform resource identifier (tenant ID).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant_id": schema.StringAttribute{
				Computed:    true,
				Description: "Tenant ID resolved from provider configuration.",
			},
			"mode": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(recipientPolicyDefaultMode),
				Description: "`observe` records what the guard would hold without changing decisions, `enforce` holds " +
					"for approval, `off` skips the check. Default `observe`.",
				Validators: []validator.String{stringvalidator.OneOf("off", "observe", "enforce")},
			},
			"internal_domains":         recipientDomainList("The workspace's own domains. Empty (the default) uses the workspace's sign-in domains. Subdomains are included."),
			"allowed_external_domains": recipientDomainList("Customer and partner domains a plain send may go to without approval. Forwards, shares and exports to them still step up."),
			"allowed_destinations": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Default:     listdefault.StaticValue(recipientEmptyList()),
				Description: "Named destinations that are not addresses, such as `patient-portal`, that need no approval.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(100),
					listvalidator.UniqueValues(),
					listvalidator.ValueStringsAre(stringvalidator.RegexMatches(recipientNamePattern, "must be lowercase letters, digits, '.', '_' or '-'")),
				},
			},
			"internal_domains_source": schema.StringAttribute{
				Computed:    true,
				Description: "`setting` when `internal_domains` is set, `sign_in_domains` when it is empty.",
			},
		},
	}
}

func (r *recipientPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func recipientListStrings(ctx context.Context, list types.List, diags *diag.Diagnostics) []string {
	out := []string{}
	if list.IsNull() || list.IsUnknown() {
		return out
	}
	diags.Append(list.ElementsAs(ctx, &out, false)...)
	return out
}

func (r *recipientPolicyResource) applyPlan(ctx context.Context, plan recipientPolicyModel, diags *diag.Diagnostics) (recipientPolicyModel, error) {
	internal := recipientListStrings(ctx, plan.InternalDomains, diags)
	external := recipientListStrings(ctx, plan.AllowedExternalDomains, diags)
	destinations := recipientListStrings(ctx, plan.AllowedDestinations, diags)
	if diags.HasError() {
		return recipientPolicyModel{}, fmt.Errorf("invalid lists")
	}
	return r.apply(ctx, plan.Mode.ValueString(), internal, external, destinations)
}

func (r *recipientPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan recipientPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.applyPlan(ctx, plan, &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError("Error setting the recipient policy", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *recipientPolicyResource) Read(ctx context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	out, err := r.client.GetRecipientPolicy(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading the recipient policy", err.Error())
		return
	}
	next := flattenRecipientPolicy(out, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *recipientPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan recipientPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.applyPlan(ctx, plan, &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError("Error updating the recipient policy", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

// Delete returns the workspace to the defaults rather than leaving whatever Terraform last set.
func (r *recipientPolicyResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if _, err := r.client.UpdateRecipientPolicy(ctx, recipientPolicyDefaultMode, []string{}, []string{}, []string{}); err != nil {
		resp.Diagnostics.AddError("Error restoring the default recipient policy", err.Error())
	}
}

func (r *recipientPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importID := strings.TrimSpace(req.ID)
	if importID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use tenant ID as import identifier.")
		return
	}
	if r.tenantID != "" && importID != r.tenantID {
		resp.Diagnostics.AddWarning(
			"Tenant mismatch",
			fmt.Sprintf("Imported tenant %q does not match provider tenant %q; provider tenant will be used.", importID, r.tenantID),
		)
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), r.tenantID)...)
}

func (r *recipientPolicyResource) apply(ctx context.Context, mode string, internal, external, destinations []string) (recipientPolicyModel, error) {
	out, err := r.client.UpdateRecipientPolicy(ctx, mode, internal, external, destinations)
	if err != nil {
		return recipientPolicyModel{}, err
	}
	return flattenRecipientPolicy(out, r.tenantID), nil
}

func recipientListFrom(value any) types.List {
	items, _ := value.([]any)
	values := make([]attr.Value, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			values = append(values, types.StringValue(text))
		}
	}
	return types.ListValueMust(types.StringType, values)
}

func flattenRecipientPolicy(out map[string]any, tenantID string) recipientPolicyModel {
	mode := tfhelpers.GetString(out, "mode")
	if mode == "" {
		mode = recipientPolicyDefaultMode
	}
	source := tfhelpers.GetString(out, "internal_domains_source")
	if source == "" {
		source = "sign_in_domains"
	}
	return recipientPolicyModel{
		ID:                     types.StringValue(tenantID),
		TenantID:               types.StringValue(tenantID),
		Mode:                   types.StringValue(mode),
		InternalDomains:        recipientListFrom(out["internal_domains"]),
		AllowedExternalDomains: recipientListFrom(out["allowed_external_domains"]),
		AllowedDestinations:    recipientListFrom(out["allowed_destinations"]),
		InternalDomainsSource:  types.StringValue(source),
	}
}
