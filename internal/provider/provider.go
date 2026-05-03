package provider

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/data_sources"
	"github.com/atensecurity/terraform-provider-thoth/internal/meta"
	"github.com/atensecurity/terraform-provider-thoth/internal/resources"
)

var _ provider.Provider = &thothProvider{}

const defaultApexDomain = "atensecurity.com"

type thothProvider struct {
	version string
}

type providerModel struct {
	APIBaseURL            types.String `tfsdk:"api_base_url"`
	TenantID              types.String `tfsdk:"tenant_id"`
	ApexDomain            types.String `tfsdk:"apex_domain"`
	AdminBearerToken      types.String `tfsdk:"admin_bearer_token"`
	AdminBearerTokenFile  types.String `tfsdk:"admin_bearer_token_file"`
	RetryMaxAttempts      types.Int64  `tfsdk:"retry_max_attempts"`
	RetryBaseDelayMs      types.Int64  `tfsdk:"retry_base_delay_ms"`
	RetryMaxDelayMs       types.Int64  `tfsdk:"retry_max_delay_ms"`
	RequestTimeoutSeconds types.Int64  `tfsdk:"request_timeout_seconds"`
	InsecureSkipTLSVerify types.Bool   `tfsdk:"insecure_skip_tls_verify"`
}

// New creates a new provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &thothProvider{version: version}
	}
}

func (p *thothProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "thoth"
	resp.Version = p.version
}

func (p *thothProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Thoth provider for headless AI Governance Control Plane operations.",
		Attributes: map[string]schema.Attribute{
			"api_base_url": schema.StringAttribute{
				Optional:    true,
				Description: "GovAPI base URL override. When omitted, provider derives https://grid.<tenant_id>.<apex_domain>.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"tenant_id": schema.StringAttribute{
				Required:    true,
				Description: "Tenant slug used in GovAPI route scoping.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"apex_domain": schema.StringAttribute{
				Optional:    true,
				Description: "Apex domain used to derive GovAPI host when api_base_url is omitted. Defaults to atensecurity.com.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"admin_bearer_token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Admin bearer token used for authenticated GovAPI requests.",
			},
			"admin_bearer_token_file": schema.StringAttribute{
				Optional:    true,
				Description: "Path to a file containing the admin bearer token.",
			},
			"retry_max_attempts": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum retry attempts for transient API/network failures.",
				Validators: []validator.Int64{
					int64validator.Between(1, 10),
				},
			},
			"retry_base_delay_ms": schema.Int64Attribute{
				Optional:    true,
				Description: "Base delay in milliseconds for exponential retry backoff.",
				Validators: []validator.Int64{
					int64validator.Between(50, 10000),
				},
			},
			"retry_max_delay_ms": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum delay in milliseconds for retry backoff.",
				Validators: []validator.Int64{
					int64validator.Between(100, 60000),
				},
			},
			"request_timeout_seconds": schema.Int64Attribute{
				Optional:    true,
				Description: "Per-request timeout in seconds.",
				Validators: []validator.Int64{
					int64validator.Between(5, 600),
				},
			},
			"insecure_skip_tls_verify": schema.BoolAttribute{
				Optional:    true,
				Description: "Skip TLS certificate verification (development/testing only).",
			},
		},
	}
}

func (p *thothProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.TenantID.IsUnknown() {
		resp.Diagnostics.AddError("Invalid provider configuration", "tenant_id must be a known value.")
		return
	}
	if config.APIBaseURL.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("api_base_url"),
			"Unknown api_base_url",
			"api_base_url must be known when provided.",
		)
		return
	}
	if config.ApexDomain.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("apex_domain"),
			"Unknown apex_domain",
			"apex_domain must be known when provided.",
		)
		return
	}

	tenantID := strings.TrimSpace(config.TenantID.ValueString())
	if tenantID == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("tenant_id"),
			"Missing tenant_id",
			"tenant_id must not be empty.",
		)
		return
	}

	apiBaseURL := strings.TrimSpace(config.APIBaseURL.ValueString())
	if apiBaseURL == "" {
		apexDomain := strings.TrimSpace(config.ApexDomain.ValueString())
		if apexDomain == "" {
			apexDomain = defaultApexDomain
		}
		apiBaseURL = fmt.Sprintf("https://grid.%s.%s", tenantID, apexDomain)
	}

	token := strings.TrimSpace(config.AdminBearerToken.ValueString())
	tokenFile := strings.TrimSpace(config.AdminBearerTokenFile.ValueString())

	if token == "" && tokenFile == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("admin_bearer_token"),
			"Missing credentials",
			"Set admin_bearer_token or admin_bearer_token_file.",
		)
		return
	}

	if token == "" && tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("admin_bearer_token_file"),
				"Cannot read token file",
				fmt.Sprintf("Unable to read %q: %v", tokenFile, err),
			)
			return
		}
		token = strings.TrimSpace(string(b))
		if token == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("admin_bearer_token_file"),
				"Empty token file",
				fmt.Sprintf("Token file %q is empty.", tokenFile),
			)
			return
		}
	}

	cfg := client.Config{
		BaseURL:               apiBaseURL,
		TenantID:              tenantID,
		AuthToken:             token,
		RetryMaxAttempts:      int(int64ValueWithDefault(config.RetryMaxAttempts, 4)),
		RetryBaseDelay:        time.Duration(int64ValueWithDefault(config.RetryBaseDelayMs, 300)) * time.Millisecond,
		RetryMaxDelay:         time.Duration(int64ValueWithDefault(config.RetryMaxDelayMs, 5000)) * time.Millisecond,
		RequestTimeout:        time.Duration(int64ValueWithDefault(config.RequestTimeoutSeconds, 30)) * time.Second,
		InsecureSkipTLSVerify: boolValueWithDefault(config.InsecureSkipTLSVerify, false),
	}

	apiClient, err := client.New(cfg)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to configure Thoth client",
			err.Error(),
		)
		return
	}

	data := &meta.ClientData{
		Client:   apiClient,
		TenantID: cfg.TenantID,
	}
	resp.DataSourceData = data
	resp.ResourceData = data
}

func (p *thothProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		resources.NewTenantSettingsResource,
		resources.NewMDMProviderResource,
		resources.NewMDMSyncResource,
		resources.NewBrowserProviderResource,
		resources.NewBrowserPolicyResource,
		resources.NewBrowserEnrollmentResource,
		resources.NewAPIKeyResource,
		resources.NewWebhookTestResource,
		resources.NewEvidenceBackfillResource,
		resources.NewDecisionFieldBackfillResource,
		resources.NewPolicySyncResource,
		resources.NewApprovalDecisionResource,
		resources.NewPackAssignmentResource,
		resources.NewPackAssignmentBulkResource,
	}
}

func (p *thothProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		data_sources.NewTenantSettingsDataSource,
		data_sources.NewGovernanceFeedDataSource,
		data_sources.NewGovernanceToolsDataSource,
		data_sources.NewGovernanceEvidenceSLOsDataSource,
		data_sources.NewAPIKeyMetricsDataSource,
		data_sources.NewMDMSyncJobDataSource,
	}
}

func int64ValueWithDefault(v types.Int64, fallback int64) int64 {
	if v.IsNull() || v.IsUnknown() {
		return fallback
	}
	return v.ValueInt64()
}

func boolValueWithDefault(v types.Bool, fallback bool) bool {
	if v.IsNull() || v.IsUnknown() {
		return fallback
	}
	return v.ValueBool()
}
