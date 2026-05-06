package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &webhookSettingsResource{}
var _ resource.ResourceWithImportState = &webhookSettingsResource{}

type webhookSettingsResource struct {
	client   *client.Client
	tenantID string
}

type webhookSettingsModel struct {
	ID                 types.String `tfsdk:"id"`
	TenantID           types.String `tfsdk:"tenant_id"`
	WebhookEnabled     types.Bool   `tfsdk:"webhook_enabled"`
	WebhookURL         types.String `tfsdk:"webhook_url"`
	WebhookSecret      types.String `tfsdk:"webhook_secret"`
	TestWebhookOnApply types.Bool   `tfsdk:"test_webhook_on_apply"`
	UpdatedAt          types.String `tfsdk:"updated_at"`
}

func NewWebhookSettingsResource() resource.Resource {
	return &webhookSettingsResource{}
}

func (r *webhookSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_webhook_settings"
}

func (r *webhookSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages tenant webhook settings.",
		Attributes: map[string]schema.Attribute{
			"id":                    schema.StringAttribute{Computed: true, Description: "Terraform resource identifier (tenant ID).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":             schema.StringAttribute{Computed: true, Description: "Tenant ID resolved from provider configuration."},
			"webhook_enabled":       schema.BoolAttribute{Optional: true, Description: "Enable outbound webhook delivery."},
			"webhook_url":           schema.StringAttribute{Optional: true, Description: "Outbound webhook URL."},
			"webhook_secret":        schema.StringAttribute{Optional: true, Sensitive: true, Description: "Webhook signing secret."},
			"test_webhook_on_apply": schema.BoolAttribute{Optional: true, Description: "Run webhook test endpoint after applying settings."},
			"updated_at":            schema.StringAttribute{Computed: true, Description: "Last update timestamp returned by GovAPI."},
		},
	}
}

func (r *webhookSettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *webhookSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan webhookSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, ok := r.apply(ctx, plan, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *webhookSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state webhookSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload, err := r.client.GetTenantSettings(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading webhook settings", err.Error())
		return
	}

	next := flattenWebhookSettings(payload, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *webhookSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan webhookSettingsModel
	var state webhookSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, ok := r.apply(ctx, plan, state, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *webhookSettingsResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No DELETE endpoint is exposed by GovAPI for tenant settings.
}

func (r *webhookSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

func (r *webhookSettingsResource) apply(
	ctx context.Context,
	plan webhookSettingsModel,
	prior webhookSettingsModel,
	diags *diag.Diagnostics,
) (webhookSettingsModel, bool) {
	existing, err := r.client.GetTenantSettings(ctx)
	if err != nil && !client.IsNotFound(err) {
		diags.AddError("Error loading current settings", err.Error())
		return webhookSettingsModel{}, false
	}
	if existing == nil {
		existing = map[string]any{}
	}

	payload := cloneMap(existing)
	applyWebhookSettingsPlan(&payload, plan, prior)

	updated, err := r.client.UpdateTenantSettings(ctx, payload)
	if err != nil {
		diags.AddError("Error updating webhook settings", err.Error())
		return webhookSettingsModel{}, false
	}

	if boolValue(plan.TestWebhookOnApply, false) {
		result, err := r.client.TestWebhook(ctx)
		if err != nil {
			diags.AddWarning("Webhook test failed", err.Error())
		} else if status := strings.ToLower(tfhelpers.GetString(result, "status")); status != "delivered" {
			diags.AddWarning("Webhook test did not report delivered", tfhelpers.ToJSONString(result))
		}
	}

	return flattenWebhookSettings(updated, plan, r.tenantID), true
}

func applyWebhookSettingsPlan(payload *map[string]any, plan webhookSettingsModel, prior webhookSettingsModel) {
	p := *payload
	webhook := tfhelpers.GetMap(p, "webhook")
	setBoolIfKnown(webhook, "enabled", plan.WebhookEnabled)
	setStringIfKnown(webhook, "url", plan.WebhookURL, types.StringNull())
	setStringIfKnown(webhook, "secret", plan.WebhookSecret, prior.WebhookSecret)
	p["webhook"] = webhook
	*payload = p
}

func flattenWebhookSettings(apiPayload map[string]any, current webhookSettingsModel, tenantID string) webhookSettingsModel {
	state := current
	state.ID = types.StringValue(tenantID)
	state.TenantID = types.StringValue(tenantID)

	webhook := tfhelpers.GetMap(apiPayload, "webhook")
	state.WebhookEnabled = types.BoolValue(tfhelpers.GetBool(webhook, "enabled"))
	state.WebhookURL = stringValueFromMap(webhook, "url")
	if v := tfhelpers.GetString(webhook, "secret"); v != "" {
		state.WebhookSecret = types.StringValue(v)
	}
	state.UpdatedAt = stringValueFromMap(apiPayload, "updated_at")
	return state
}
