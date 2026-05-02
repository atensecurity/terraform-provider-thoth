package resources

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &webhookTestResource{}
var _ resource.ResourceWithImportState = &webhookTestResource{}

type webhookTestResource struct {
	client   *client.Client
	tenantID string
}

type webhookTestModel struct {
	ID         types.String `tfsdk:"id"`
	TenantID   types.String `tfsdk:"tenant_id"`
	Trigger    types.String `tfsdk:"trigger"`
	Status     types.String `tfsdk:"status"`
	HTTPStatus types.Int64  `tfsdk:"http_status"`
	Error      types.String `tfsdk:"error"`
	TestedAt   types.String `tfsdk:"tested_at"`
}

func NewWebhookTestResource() resource.Resource {
	return &webhookTestResource{}
}

func (r *webhookTestResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_webhook_test"
}

func (r *webhookTestResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Triggers Thoth webhook test delivery for tenant settings.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, Description: "Synthetic test execution ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":   schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"trigger":     schema.StringAttribute{Optional: true, Description: "Change this value to force a re-test.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"status":      schema.StringAttribute{Computed: true, Description: "Webhook test status (delivered or failed)."},
			"http_status": schema.Int64Attribute{Computed: true, Description: "HTTP status returned by webhook endpoint (if available)."},
			"error":       schema.StringAttribute{Computed: true, Description: "Error string returned by webhook test endpoint."},
			"tested_at":   schema.StringAttribute{Computed: true, Description: "Timestamp when the test was executed."},
		},
	}
}

func (r *webhookTestResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *webhookTestResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan webhookTestModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.runTest(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Webhook test failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *webhookTestResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state webhookTestModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// No GET endpoint exists for historical webhook tests; preserve prior state.
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *webhookTestResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan webhookTestModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	next, err := r.runTest(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Webhook test failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *webhookTestResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No remote delete operation.
}

func (r *webhookTestResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importID := strings.TrimSpace(req.ID)
	if importID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use any non-empty ID, for example the prior tested_at timestamp.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), importID)...)
}

func (r *webhookTestResource) runTest(ctx context.Context, plan webhookTestModel) (webhookTestModel, error) {
	row, err := r.client.TestWebhook(ctx)
	if err != nil {
		return webhookTestModel{}, err
	}
	testedAt := time.Now().UTC().Format(time.RFC3339)
	id := fmt.Sprintf("%s/%s", r.tenantID, testedAt)

	next := plan
	next.ID = types.StringValue(id)
	next.TenantID = types.StringValue(r.tenantID)
	next.Status = nullableString(row, "status")
	next.HTTPStatus = types.Int64Value(tfhelpers.GetInt64(row, "http_status"))
	next.Error = nullableString(row, "error")
	next.TestedAt = types.StringValue(testedAt)
	return next, nil
}
