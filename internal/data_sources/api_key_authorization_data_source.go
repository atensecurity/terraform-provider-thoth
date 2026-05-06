package data_sources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &apiKeyAuthorizationDataSource{}

type apiKeyAuthorizationDataSource struct {
	client *client.Client
}

type apiKeyAuthorizationModel struct {
	KeyID        types.String `tfsdk:"key_id"`
	APIKey       types.String `tfsdk:"api_key"`
	Permission   types.String `tfsdk:"permission"`
	ResourceType types.String `tfsdk:"resource_type"`
	ResourceID   types.String `tfsdk:"resource_id"`

	Authorized        types.Bool   `tfsdk:"authorized"`
	Valid             types.Bool   `tfsdk:"valid"`
	PermissionAllowed types.Bool   `tfsdk:"permission_allowed"`
	ScopeAllowed      types.Bool   `tfsdk:"scope_allowed"`
	Expired           types.Bool   `tfsdk:"expired"`
	ScopeLevel        types.String `tfsdk:"scope_level"`
	ScopeTargetID     types.String `tfsdk:"scope_target_id"`
	ValidatedAt       types.String `tfsdk:"validated_at"`
	ResponseJSON      types.String `tfsdk:"response_json"`
}

func NewAPIKeyAuthorizationDataSource() datasource.DataSource {
	return &apiKeyAuthorizationDataSource{}
}

func (d *apiKeyAuthorizationDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_key_authorization"
}

func (d *apiKeyAuthorizationDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Validates API key material, permission, and scope against a target resource.",
		Attributes: map[string]schema.Attribute{
			"key_id": schema.StringAttribute{
				Required:    true,
				Description: "Scoped key ID to authorize.",
			},
			"api_key": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Plaintext API key material for validation.",
			},
			"permission": schema.StringAttribute{
				Required:    true,
				Description: "Permission to validate: read, write, or execute.",
			},
			"resource_type": schema.StringAttribute{
				Required:    true,
				Description: "Target resource type: organization, fleet, endpoint, or agent.",
			},
			"resource_id": schema.StringAttribute{
				Optional:    true,
				Description: "Target resource ID (required unless resource_type=organization).",
			},
			"authorized": schema.BoolAttribute{
				Computed:    true,
				Description: "True when valid, permission_allowed, and scope_allowed are all true.",
			},
			"valid": schema.BoolAttribute{
				Computed:    true,
				Description: "True when key material is valid and not revoked.",
			},
			"permission_allowed": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the key grants the requested permission.",
			},
			"scope_allowed": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the key scope permits the requested resource.",
			},
			"expired": schema.BoolAttribute{
				Computed:    true,
				Description: "True when key expiry has elapsed.",
			},
			"scope_level": schema.StringAttribute{
				Computed:    true,
				Description: "Stored key scope level.",
			},
			"scope_target_id": schema.StringAttribute{
				Computed:    true,
				Description: "Stored key scope target identifier.",
			},
			"validated_at": schema.StringAttribute{
				Computed:    true,
				Description: "RFC3339 timestamp for the authorization check.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Raw authorization response as JSON.",
			},
		},
	}
}

func (d *apiKeyAuthorizationDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *apiKeyAuthorizationDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state apiKeyAuthorizationModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyID := strings.TrimSpace(state.KeyID.ValueString())
	if keyID == "" {
		resp.Diagnostics.AddAttributeError(path.Root("key_id"), "Missing key_id", "key_id must be set.")
		return
	}
	apiKey := strings.TrimSpace(state.APIKey.ValueString())
	if apiKey == "" {
		resp.Diagnostics.AddAttributeError(path.Root("api_key"), "Missing api_key", "api_key must be set.")
		return
	}
	permission := strings.ToLower(strings.TrimSpace(state.Permission.ValueString()))
	if permission == "" {
		resp.Diagnostics.AddAttributeError(path.Root("permission"), "Missing permission", "permission must be set.")
		return
	}
	resourceType := strings.ToLower(strings.TrimSpace(state.ResourceType.ValueString()))
	if resourceType == "" {
		resp.Diagnostics.AddAttributeError(path.Root("resource_type"), "Missing resource_type", "resource_type must be set.")
		return
	}
	resourceID := strings.TrimSpace(state.ResourceID.ValueString())

	switch resourceType {
	case "organization", "fleet", "endpoint", "agent":
		// Valid.
	default:
		resp.Diagnostics.AddAttributeError(
			path.Root("resource_type"),
			"Invalid resource_type",
			"resource_type must be one of: organization, fleet, endpoint, agent.",
		)
		return
	}

	if resourceType != "organization" && resourceID == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("resource_id"),
			"Missing resource_id",
			"resource_id must be set when resource_type is fleet, endpoint, or agent.",
		)
		return
	}

	payload := map[string]any{
		"api_key":       apiKey,
		"permission":    permission,
		"resource_type": resourceType,
		"resource_id":   resourceID,
	}

	result, err := d.client.AuthorizeAPIKey(ctx, keyID, payload)
	if err != nil {
		resp.Diagnostics.AddError("Error authorizing API key", err.Error())
		return
	}

	state.Valid = types.BoolValue(tfhelpers.GetBool(result, "valid"))
	state.PermissionAllowed = types.BoolValue(tfhelpers.GetBool(result, "permission_allowed"))
	state.ScopeAllowed = types.BoolValue(tfhelpers.GetBool(result, "scope_allowed"))
	state.Expired = types.BoolValue(tfhelpers.GetBool(result, "expired"))
	state.ScopeLevel = nullableString(result, "scope_level")
	state.ScopeTargetID = nullableString(result, "scope_target_id")
	state.ValidatedAt = nullableString(result, "validated_at")
	state.Authorized = types.BoolValue(
		tfhelpers.GetBool(result, "valid") &&
			tfhelpers.GetBool(result, "permission_allowed") &&
			tfhelpers.GetBool(result, "scope_allowed"),
	)
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
