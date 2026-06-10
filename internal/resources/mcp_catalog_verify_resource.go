package resources

import (
	"context"
	"encoding/json"
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

var _ resource.Resource = &mcpCatalogVerifyResource{}
var _ resource.ResourceWithImportState = &mcpCatalogVerifyResource{}

type mcpCatalogVerifyResource struct {
	client   *client.Client
	tenantID string
}

type mcpCatalogVerifyModel struct {
	ID                types.String `tfsdk:"id"`
	TenantID          types.String `tfsdk:"tenant_id"`
	Trigger           types.String `tfsdk:"trigger"`
	Environment       types.String `tfsdk:"environment"`
	Principal         types.String `tfsdk:"principal"`
	HumanRole         types.String `tfsdk:"human_role"`
	HumanPrincipal    types.String `tfsdk:"human_principal"`
	HumanGroups       types.List   `tfsdk:"human_groups"`
	AuthContextJSON   types.String `tfsdk:"auth_context_json"`
	PolicyCount       types.Int64  `tfsdk:"policy_count"`
	AllowedToolsCount types.Int64  `tfsdk:"allowed_tools_count"`
	BlockedToolsCount types.Int64  `tfsdk:"blocked_tools_count"`
	VerifiedAt        types.String `tfsdk:"verified_at"`
	ResponseJSON      types.String `tfsdk:"response_json"`
}

func NewMCPCatalogVerifyResource() resource.Resource {
	return &mcpCatalogVerifyResource{}
}

func (r *mcpCatalogVerifyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mcp_catalog_verify"
}

func (r *mcpCatalogVerifyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Verifies the grants-derived MCP tool catalog for a principal/role and stores the check result.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Synthetic verification ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"tenant_id": schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"trigger": schema.StringAttribute{
				Optional:      true,
				Description:   "Change this field to force another verification run.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"environment": schema.StringAttribute{Optional: true, Description: "Optional environment filter (dev/prod)."},
			"principal": schema.StringAttribute{
				Optional:    true,
				Description: "Principal used for catalog verification.",
			},
			"human_role": schema.StringAttribute{
				Optional:    true,
				Description: "Optional human role seed for catalog verification.",
			},
			"human_principal": schema.StringAttribute{
				Optional:    true,
				Description: "Optional human principal seed for catalog verification.",
			},
			"human_groups": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Optional human groups for catalog verification context.",
			},
			"auth_context_json": schema.StringAttribute{
				Optional:    true,
				Description: "Optional auth context JSON object merged into the verification request.",
			},
			"policy_count":        schema.Int64Attribute{Computed: true, Description: "Matched policy count returned by the verifier."},
			"allowed_tools_count": schema.Int64Attribute{Computed: true, Description: "Number of allowed tools in the result catalog."},
			"blocked_tools_count": schema.Int64Attribute{Computed: true, Description: "Number of blocked tools in the result catalog."},
			"verified_at":         schema.StringAttribute{Computed: true, Description: "RFC3339 timestamp when verification ran."},
			"response_json":       schema.StringAttribute{Computed: true, Description: "Catalog verification response payload as JSON."},
		},
	}
}

func (r *mcpCatalogVerifyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *mcpCatalogVerifyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan mcpCatalogVerifyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, err := r.runVerification(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("MCP catalog verification failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *mcpCatalogVerifyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state mcpCatalogVerifyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// No historical read endpoint exists; preserve state.
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *mcpCatalogVerifyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan mcpCatalogVerifyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, err := r.runVerification(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("MCP catalog verification failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *mcpCatalogVerifyResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No remote delete operation.
}

func (r *mcpCatalogVerifyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importID := strings.TrimSpace(req.ID)
	if importID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use any non-empty ID, such as a prior verified_at timestamp.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), importID)...)
}

func (r *mcpCatalogVerifyResource) runVerification(ctx context.Context, plan mcpCatalogVerifyModel) (mcpCatalogVerifyModel, error) {
	payload := map[string]any{}
	if principal := strings.TrimSpace(plan.Principal.ValueString()); principal != "" {
		payload["principal"] = principal
	}
	if role := strings.TrimSpace(plan.HumanRole.ValueString()); role != "" {
		payload["human_role"] = role
	}
	if humanPrincipal := strings.TrimSpace(plan.HumanPrincipal.ValueString()); humanPrincipal != "" {
		payload["human_principal"] = humanPrincipal
	}
	if !plan.HumanGroups.IsNull() && !plan.HumanGroups.IsUnknown() {
		var groups []string
		if diags := plan.HumanGroups.ElementsAs(ctx, &groups, false); diags.HasError() {
			return mcpCatalogVerifyModel{}, fmt.Errorf("decode human_groups")
		}
		if len(groups) > 0 {
			payload["human_groups"] = groups
		}
	}
	if authContextRaw := strings.TrimSpace(plan.AuthContextJSON.ValueString()); authContextRaw != "" {
		authContext := map[string]any{}
		if err := json.Unmarshal([]byte(authContextRaw), &authContext); err != nil {
			return mcpCatalogVerifyModel{}, fmt.Errorf("auth_context_json must be valid JSON object: %w", err)
		}
		payload["auth_context"] = authContext
	}
	if len(payload) == 0 {
		return mcpCatalogVerifyModel{}, fmt.Errorf("at least one of principal, human_role, human_principal, human_groups, or auth_context_json must be set")
	}

	environment := strings.TrimSpace(plan.Environment.ValueString())
	result, err := r.client.VerifyMCPCatalog(ctx, environment, payload)
	if err != nil {
		return mcpCatalogVerifyModel{}, err
	}

	allowedToolsCount := countStringList(result["allowed_tools"])
	blockedToolsCount := countStringList(result["blocked_tools"])
	policyCount := int64FromResult(result["policy_count"])
	if policyCount == 0 {
		policyCount = int64(countAnyList(result["matched_policies"]))
	}

	verifiedAt := time.Now().UTC().Format(time.RFC3339)
	next := plan
	next.ID = types.StringValue(fmt.Sprintf("%s/%s", r.tenantID, verifiedAt))
	next.TenantID = types.StringValue(r.tenantID)
	next.PolicyCount = types.Int64Value(policyCount)
	next.AllowedToolsCount = types.Int64Value(allowedToolsCount)
	next.BlockedToolsCount = types.Int64Value(blockedToolsCount)
	next.VerifiedAt = types.StringValue(verifiedAt)
	next.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(result))
	return next, nil
}

func countStringList(input any) int64 {
	rows, ok := input.([]any)
	if !ok {
		return 0
	}
	var total int64
	for _, row := range rows {
		if strings.TrimSpace(fmt.Sprintf("%v", row)) != "" {
			total++
		}
	}
	return total
}

func countAnyList(input any) int {
	rows, ok := input.([]any)
	if !ok {
		return 0
	}
	return len(rows)
}

func int64FromResult(input any) int64 {
	switch typed := input.(type) {
	case int64:
		return typed
	case int32:
		return int64(typed)
	case int:
		return int64(typed)
	case float64:
		return int64(typed)
	case float32:
		return int64(typed)
	default:
		return 0
	}
}
