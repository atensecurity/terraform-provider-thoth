package resources

import (
	"context"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &agentResource{}
var _ resource.ResourceWithImportState = &agentResource{}

type agentResource struct {
	client *client.Client
}

type agentModel struct {
	ID            types.String `tfsdk:"id"`
	AgentID       types.String `tfsdk:"agent_id"`
	DisplayName   types.String `tfsdk:"display_name"`
	OwnerEmail    types.String `tfsdk:"owner_email"`
	ApprovedScope types.Set    `tfsdk:"approved_scope"`
	Status        types.String `tfsdk:"status"`
}

func NewAgentResource() resource.Resource {
	return &agentResource{}
}

func (r *agentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent"
}

func (r *agentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A registered agent: its display name, owner and the tools it is meant to use. Registering an agent " +
			"lets you set its mode (`thoth_agent_enforcement`), profile (`thoth_pack_assignment`) and tool declarations. " +
			"It never changes the agent's mode or a quarantine. Thoth keeps an agent's registration with its decision " +
			"history, so destroying this resource only removes it from Terraform state.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Terraform resource identifier (agent ID).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"agent_id": schema.StringAttribute{
				Required:      true,
				Description:   "The agent ID the agent's SDK or proxy sends.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"display_name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The name shown in the dashboard and reports. Defaults to the agent ID.",
			},
			"owner_email": schema.StringAttribute{
				Optional:    true,
				Description: "The person responsible for the agent.",
			},
			"approved_scope": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
				Description: "Tool names the agent is meant to use; the rules weigh calls outside it as out of scope.",
			},
			"status": schema.StringAttribute{
				Computed:      true,
				Description:   "`active`, or `quarantined` when Thoth denies the agent's actions.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *agentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if data := tfhelpers.RequireResourceClient(req, resp); data != nil {
		r.client = data.Client
	}
}

func (r *agentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan agentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.apply(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error registering agent", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *agentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state agentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetAgent(ctx, state.AgentID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading agent", err.Error())
		return
	}
	next := flattenAgent(out, state.AgentID.ValueString(), state.OwnerEmail)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *agentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan agentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.apply(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Error updating agent registration", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *agentResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning("Agent registration kept",
		"Thoth keeps an agent's registration with its decision history, so this only removes the agent from Terraform state. "+
			"To stop it acting, quarantine it (thothctl agents quarantine set) or revoke its API keys.")
}

func (r *agentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	agentID := strings.TrimSpace(req.ID)
	if agentID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use the agent ID as the import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), agentID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("agent_id"), agentID)...)
}

func (r *agentResource) apply(ctx context.Context, plan agentModel) (agentModel, error) {
	agentID := plan.AgentID.ValueString()
	scope := []string{}
	for _, value := range plan.ApprovedScope.Elements() {
		if s, ok := value.(basetypes.StringValue); ok {
			scope = append(scope, s.ValueString())
		}
	}
	sort.Strings(scope)
	displayName := plan.DisplayName.ValueString()
	if plan.DisplayName.IsUnknown() || plan.DisplayName.IsNull() {
		displayName = ""
	}
	if _, err := r.client.RegisterAgent(ctx, agentID, displayName, plan.OwnerEmail.ValueString(), scope); err != nil {
		return agentModel{}, err
	}
	// Read back what Thoth stored, including its default display name.
	out, err := r.client.GetAgent(ctx, agentID)
	if err != nil {
		return agentModel{}, err
	}
	return flattenAgent(out, agentID, plan.OwnerEmail), nil
}

// flattenAgent maps the agent record. owner_email keeps null when it is unset
// in configuration and Thoth stored it empty.
func flattenAgent(out map[string]any, agentID string, configuredOwner types.String) agentModel {
	scope := tfhelpers.GetStringSlice(out, "approved_scope")
	sort.Strings(scope)
	values := make([]attr.Value, 0, len(scope))
	for _, s := range scope {
		values = append(values, types.StringValue(s))
	}
	owner := types.StringNull()
	if stored := tfhelpers.GetString(out, "owner_email"); stored != "" || !configuredOwner.IsNull() {
		owner = types.StringValue(stored)
	}
	displayName := tfhelpers.GetString(out, "display_name")
	if displayName == "" {
		displayName = agentID
	}
	return agentModel{
		ID:            types.StringValue(agentID),
		AgentID:       types.StringValue(agentID),
		DisplayName:   types.StringValue(displayName),
		OwnerEmail:    owner,
		ApprovedScope: types.SetValueMust(types.StringType, values),
		Status:        types.StringValue(tfhelpers.GetString(out, "status")),
	}
}
