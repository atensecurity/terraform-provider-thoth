package resources

import (
	"context"
	"fmt"
	"net/http"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type toolClassificationResource struct{ client *client.Client }
type toolClassificationModel struct {
	ID        types.String `tfsdk:"id"`
	ToolName  types.String `tfsdk:"tool_name"`
	AgentID   types.String `tfsdk:"agent_id"`
	Classes   types.Set    `tfsdk:"classes"`
	CreatedBy types.String `tfsdk:"created_by"`
	CreatedAt types.String `tfsdk:"created_at"`
}

func NewToolClassificationResource() resource.Resource { return &toolClassificationResource{} }
func (r *toolClassificationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tool_classification"
}
func (r *toolClassificationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Declare reviewed tool effects. Requires tenant admin authentication, or an approver when no admin exists.", Attributes: map[string]schema.Attribute{
		"id":         schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"tool_name":  schema.StringAttribute{Required: true, Description: "Exact tool name; wildcards are refused."},
		"agent_id":   schema.StringAttribute{Optional: true, Description: "Optional agent scope; omit for tenant-wide authority. Changing scope replaces the declaration.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"classes":    schema.SetAttribute{Required: true, ElementType: types.StringType, Description: "Reviewed effects: read, write, delete, execute, export, external_call, bulk_operation, credential_access, sensitive_data_access."},
		"created_by": schema.StringAttribute{Computed: true}, "created_at": schema.StringAttribute{Computed: true},
	}}
}
func (r *toolClassificationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if data := tfhelpers.RequireResourceClient(req, resp); data != nil {
		r.client = data.Client
	}
}
func (r *toolClassificationResource) write(ctx context.Context, model *toolClassificationModel, method string) error {
	var classes []string
	diags := model.Classes.ElementsAs(ctx, &classes, false)
	if diags.HasError() {
		return fmt.Errorf("invalid classes")
	}
	id := model.ID.ValueString()
	if method == http.MethodPost {
		id = ""
	}
	body := map[string]any{"tool_name": model.ToolName.ValueString(), "classes": classes}
	if !model.AgentID.IsNull() && !model.AgentID.IsUnknown() {
		body["agent_id"] = model.AgentID.ValueString()
	}
	row, err := r.client.ToolClassification(ctx, method, id, body)
	if err != nil {
		return err
	}
	return r.flatten(ctx, model, row)
}
func (r *toolClassificationResource) flatten(ctx context.Context, model *toolClassificationModel, row map[string]any) error {
	model.ID = types.StringValue(tfhelpers.GetString(row, "id"))
	model.ToolName = types.StringValue(tfhelpers.GetString(row, "tool_name"))
	model.AgentID = types.StringNull()
	if agent := tfhelpers.GetString(row, "agent_id"); agent != "" {
		model.AgentID = types.StringValue(agent)
	}
	classes, diags := types.SetValueFrom(ctx, types.StringType, tfhelpers.GetStringSlice(row, "classes"))
	if diags.HasError() {
		return fmt.Errorf("invalid server classes")
	}
	model.Classes = classes
	model.CreatedBy = types.StringValue(tfhelpers.GetString(row, "created_by"))
	model.CreatedAt = types.StringValue(tfhelpers.GetString(row, "created_at"))
	return nil
}
func (r *toolClassificationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model toolClassificationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.write(ctx, &model, http.MethodPost); err != nil {
		resp.Diagnostics.AddError("Tool confirmation failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
func (r *toolClassificationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model toolClassificationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.write(ctx, &model, http.MethodPut); err != nil {
		resp.Diagnostics.AddError("Tool confirmation failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
func (r *toolClassificationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var model toolClassificationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	row, err := r.client.ToolClassification(ctx, http.MethodGet, model.ID.ValueString(), nil)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Read tool classification failed", err.Error())
		return
	}
	if err := r.flatten(ctx, &model, row); err != nil {
		resp.Diagnostics.AddError("Invalid tool classification", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
func (r *toolClassificationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var model toolClassificationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.ToolClassification(ctx, http.MethodDelete, model.ID.ValueString(), nil)
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Delete tool classification failed", err.Error())
	}
}
