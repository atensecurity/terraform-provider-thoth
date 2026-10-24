package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

// Private defaults, matching Thoth's behavior for a workspace that has not chosen.
const (
	dataHandlingDefaultToolArguments = "hash"
	dataHandlingDefaultPrompts       = "drop"
)

var _ resource.Resource = &dataHandlingResource{}
var _ resource.ResourceWithImportState = &dataHandlingResource{}

type dataHandlingResource struct {
	client   *client.Client
	tenantID string
}

type dataHandlingModel struct {
	ID            types.String `tfsdk:"id"`
	TenantID      types.String `tfsdk:"tenant_id"`
	ToolArguments types.String `tfsdk:"tool_arguments"`
	Prompts       types.String `tfsdk:"prompts"`
}

func NewDataHandlingResource() resource.Resource {
	return &dataHandlingResource{}
}

func (r *dataHandlingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_data_handling"
}

func (r *dataHandlingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "What Thoth keeps of your agents' tool arguments, prompts and tool output. " +
			"Applied when data reaches Thoth, before it is queued or stored. Destroying this resource " +
			"returns the workspace to the private defaults: hashed arguments and no prompts.",
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
			"tool_arguments": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(dataHandlingDefaultToolArguments),
				Description: "Tool arguments: `store` as sent, `hash` each value with a workspace-keyed HMAC " +
					"(argument names kept), `redact` each value to its type, or `drop`. Default `hash`.",
				Validators: []validator.String{stringvalidator.OneOf("store", "hash", "redact", "drop")},
			},
			"prompts": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(dataHandlingDefaultPrompts),
				Description: "Prompts, model output and tool results: `store`, `hash` the whole text with a " +
					"workspace-keyed HMAC, or `drop`. Default `drop`.",
				Validators: []validator.String{stringvalidator.OneOf("store", "hash", "drop")},
			},
		},
	}
}

func (r *dataHandlingResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *dataHandlingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dataHandlingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.apply(ctx, plan.ToolArguments.ValueString(), plan.Prompts.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error setting data handling", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *dataHandlingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	out, err := r.client.GetDataHandling(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading data handling", err.Error())
		return
	}
	next := flattenDataHandling(out, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *dataHandlingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan dataHandlingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.apply(ctx, plan.ToolArguments.ValueString(), plan.Prompts.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error updating data handling", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

// Delete returns the workspace to the private defaults rather than leaving
// whatever Terraform last set.
func (r *dataHandlingResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if _, err := r.client.UpdateDataHandling(ctx, dataHandlingDefaultToolArguments, dataHandlingDefaultPrompts); err != nil {
		resp.Diagnostics.AddError("Error restoring default data handling", err.Error())
	}
}

func (r *dataHandlingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

func (r *dataHandlingResource) apply(ctx context.Context, toolArguments, prompts string) (dataHandlingModel, error) {
	out, err := r.client.UpdateDataHandling(ctx, toolArguments, prompts)
	if err != nil {
		return dataHandlingModel{}, err
	}
	return flattenDataHandling(out, r.tenantID), nil
}

func flattenDataHandling(out map[string]any, tenantID string) dataHandlingModel {
	args := tfhelpers.GetString(out, "tool_arguments")
	if args == "" {
		args = dataHandlingDefaultToolArguments
	}
	prompts := tfhelpers.GetString(out, "prompts")
	if prompts == "" {
		prompts = dataHandlingDefaultPrompts
	}
	return dataHandlingModel{
		ID:            types.StringValue(tenantID),
		TenantID:      types.StringValue(tenantID),
		ToolArguments: types.StringValue(args),
		Prompts:       types.StringValue(prompts),
	}
}
