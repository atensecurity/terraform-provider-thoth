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

var _ resource.Resource = &siemSettingsResource{}
var _ resource.ResourceWithImportState = &siemSettingsResource{}

type siemSettingsResource struct {
	client   *client.Client
	tenantID string
}

type siemSettingsModel struct {
	ID                  types.String `tfsdk:"id"`
	TenantID            types.String `tfsdk:"tenant_id"`
	SIEMProvider        types.String `tfsdk:"siem_provider"`
	SIEMWebhookEnabled  types.Bool   `tfsdk:"siem_webhook_enabled"`
	SIEMWebhookURL      types.String `tfsdk:"siem_webhook_url"`
	SIEMWebhookSecret   types.String `tfsdk:"siem_webhook_secret"`
	SIEMWebhookProvider types.String `tfsdk:"siem_webhook_provider"`
	UpdatedAt           types.String `tfsdk:"updated_at"`
}

func NewSIEMSettingsResource() resource.Resource {
	return &siemSettingsResource{}
}

func (r *siemSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_siem_settings"
}

func (r *siemSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages tenant SIEM integration settings.",
		Attributes: map[string]schema.Attribute{
			"id":                    schema.StringAttribute{Computed: true, Description: "Terraform resource identifier (tenant ID).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant_id":             schema.StringAttribute{Computed: true, Description: "Tenant ID resolved from provider configuration."},
			"siem_provider":         schema.StringAttribute{Optional: true, Description: "SIEM provider slug."},
			"siem_webhook_enabled":  schema.BoolAttribute{Optional: true, Description: "Enable SIEM webhook delivery."},
			"siem_webhook_url":      schema.StringAttribute{Optional: true, Description: "SIEM webhook URL."},
			"siem_webhook_secret":   schema.StringAttribute{Optional: true, Sensitive: true, Description: "SIEM webhook signing secret."},
			"siem_webhook_provider": schema.StringAttribute{Optional: true, Description: "SIEM webhook provider slug."},
			"updated_at":            schema.StringAttribute{Computed: true, Description: "Last update timestamp returned by GovAPI."},
		},
	}
}

func (r *siemSettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *siemSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan siemSettingsModel
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

func (r *siemSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state siemSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload, err := r.client.GetTenantSettings(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading SIEM settings", err.Error())
		return
	}

	next := flattenSIEMSettings(payload, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *siemSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan siemSettingsModel
	var state siemSettingsModel
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

func (r *siemSettingsResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No DELETE endpoint is exposed by GovAPI for tenant settings.
}

func (r *siemSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

func (r *siemSettingsResource) apply(
	ctx context.Context,
	plan siemSettingsModel,
	prior siemSettingsModel,
	diags *diag.Diagnostics,
) (siemSettingsModel, bool) {
	existing, err := r.client.GetTenantSettings(ctx)
	if err != nil && !client.IsNotFound(err) {
		diags.AddError("Error loading current settings", err.Error())
		return siemSettingsModel{}, false
	}
	if existing == nil {
		existing = map[string]any{}
	}

	payload := cloneMap(existing)
	applySIEMSettingsPlan(&payload, plan, prior)

	updated, err := r.client.UpdateTenantSettings(ctx, payload)
	if err != nil {
		diags.AddError("Error updating SIEM settings", err.Error())
		return siemSettingsModel{}, false
	}

	return flattenSIEMSettings(updated, plan, r.tenantID), true
}

func applySIEMSettingsPlan(payload *map[string]any, plan siemSettingsModel, prior siemSettingsModel) {
	p := *payload
	siem := tfhelpers.GetMap(p, "siem")
	setStringIfKnown(siem, "provider", plan.SIEMProvider, types.StringNull())
	siemWebhook := tfhelpers.GetMap(siem, "webhook")
	setBoolIfKnown(siemWebhook, "enabled", plan.SIEMWebhookEnabled)
	setStringIfKnown(siemWebhook, "url", plan.SIEMWebhookURL, types.StringNull())
	setStringIfKnown(siemWebhook, "secret", plan.SIEMWebhookSecret, prior.SIEMWebhookSecret)
	setStringIfKnown(siemWebhook, "provider", plan.SIEMWebhookProvider, types.StringNull())
	siem["webhook"] = siemWebhook
	p["siem"] = siem
	*payload = p
}

func flattenSIEMSettings(apiPayload map[string]any, current siemSettingsModel, tenantID string) siemSettingsModel {
	state := current
	state.ID = types.StringValue(tenantID)
	state.TenantID = types.StringValue(tenantID)

	siem := tfhelpers.GetMap(apiPayload, "siem")
	state.SIEMProvider = stringValueFromMap(siem, "provider")
	siemWebhook := tfhelpers.GetMap(siem, "webhook")
	state.SIEMWebhookEnabled = types.BoolValue(tfhelpers.GetBool(siemWebhook, "enabled"))
	state.SIEMWebhookURL = stringValueFromMap(siemWebhook, "url")
	if v := tfhelpers.GetString(siemWebhook, "secret"); v != "" {
		state.SIEMWebhookSecret = types.StringValue(v)
	}
	state.SIEMWebhookProvider = stringValueFromMap(siemWebhook, "provider")
	state.UpdatedAt = stringValueFromMap(apiPayload, "updated_at")
	return state
}
