package data_sources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &tenantSettingsDataSource{}

type tenantSettingsDataSource struct {
	client   *client.Client
	tenantID string
}

type tenantSettingsDataSourceModel struct {
	TenantID          types.String `tfsdk:"tenant_id"`
	ComplianceProfile types.String `tfsdk:"compliance_profile"`
	RegulatoryRegimes types.List   `tfsdk:"regulatory_regimes"`
	UpdatedAt         types.String `tfsdk:"updated_at"`
	SettingsJSON      types.String `tfsdk:"settings_json"`
	ToolRiskOverrides types.Map    `tfsdk:"tool_risk_overrides"`
	WebhookEnabled    types.Bool   `tfsdk:"webhook_enabled"`
	WebhookURL        types.String `tfsdk:"webhook_url"`
}

func NewTenantSettingsDataSource() datasource.DataSource {
	return &tenantSettingsDataSource{}
}

func (d *tenantSettingsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant_settings"
}

func (d *tenantSettingsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads current tenant-wide Thoth settings.",
		Attributes: map[string]schema.Attribute{
			"tenant_id":           schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"compliance_profile":  schema.StringAttribute{Computed: true, Description: "Current compliance profile."},
			"regulatory_regimes":  schema.ListAttribute{Computed: true, ElementType: types.StringType, Description: "Configured regulatory regimes used for baseline pack auto-loading."},
			"updated_at":          schema.StringAttribute{Computed: true, Description: "Last settings update timestamp."},
			"settings_json":       schema.StringAttribute{Computed: true, Description: "Full settings payload as JSON."},
			"tool_risk_overrides": schema.MapAttribute{Computed: true, ElementType: types.StringType, Description: "Tool risk tier overrides."},
			"webhook_enabled":     schema.BoolAttribute{Computed: true, Description: "Whether webhook delivery is enabled."},
			"webhook_url":         schema.StringAttribute{Computed: true, Description: "Configured webhook URL."},
		},
	}
}

func (d *tenantSettingsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
	d.tenantID = data.TenantID
}

func (d *tenantSettingsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	payload, err := d.client.GetTenantSettings(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading tenant settings", err.Error())
		return
	}

	toolRisk := tfhelpers.StringMapValue(tfhelpers.GetStringMap(payload, "tool_risk_overrides"))
	webhook := tfhelpers.GetMap(payload, "webhook")

	state := tenantSettingsDataSourceModel{
		TenantID:          types.StringValue(d.tenantID),
		ComplianceProfile: nullableString(payload, "compliance_profile"),
		RegulatoryRegimes: tfhelpers.StringSliceValue(tfhelpers.GetStringSlice(payload, "regulatory_regimes")),
		UpdatedAt:         nullableString(payload, "updated_at"),
		SettingsJSON:      types.StringValue(tfhelpers.ToJSONString(payload)),
		ToolRiskOverrides: toolRisk,
		WebhookEnabled:    types.BoolValue(tfhelpers.GetBool(webhook, "enabled")),
		WebhookURL:        nullableString(webhook, "url"),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
