package resources

import (
	"context"
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

var _ resource.Resource = &endpointResource{}
var _ resource.ResourceWithImportState = &endpointResource{}

type endpointResource struct {
	client   *client.Client
	tenantID string
}

type endpointResourceModel struct {
	ID               types.String  `tfsdk:"id"`
	EndpointID       types.String  `tfsdk:"endpoint_id"`
	TenantID         types.String  `tfsdk:"tenant_id"`
	Hostname         types.String  `tfsdk:"hostname"`
	EmployeeName     types.String  `tfsdk:"employee_name"`
	EmployeeEmail    types.String  `tfsdk:"employee_email"`
	Department       types.String  `tfsdk:"department"`
	OS               types.String  `tfsdk:"os"`
	OSVersion        types.String  `tfsdk:"os_version"`
	Enrollment       types.String  `tfsdk:"enrollment"`
	Status           types.String  `tfsdk:"status"`
	EnforcementMode  types.String  `tfsdk:"enforcement_mode"`
	Environment      types.String  `tfsdk:"environment"`
	ProxyVersion     types.String  `tfsdk:"proxy_version"`
	AgentIDs         types.List    `tfsdk:"agent_ids"`
	RiskScore        types.Float64 `tfsdk:"risk_score"`
	ViolationsToday  types.Int64   `tfsdk:"violations_today"`
	SessionsToday    types.Int64   `tfsdk:"sessions_today"`
	FleetID          types.String  `tfsdk:"fleet_id"`
	ProviderName     types.String  `tfsdk:"provider_name"`
	RuntimeAuthMode  types.String  `tfsdk:"runtime_auth_mode"`
	IdentityBinding  types.String  `tfsdk:"identity_binding_user"`
	ManagedRuntimeID types.String  `tfsdk:"managed_runtime_key_id"`
	LastSeen         types.String  `tfsdk:"last_seen"`
	CreatedAt        types.String  `tfsdk:"created_at"`
	UpdatedAt        types.String  `tfsdk:"updated_at"`
}

func NewEndpointResource() resource.Resource {
	return &endpointResource{}
}

func (r *endpointResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_endpoint"
}

func (r *endpointResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Registers and manages a Thoth endpoint record for a tenant.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource ID (endpoint_id).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"endpoint_id": schema.StringAttribute{
				Required:      true,
				Description:   "Endpoint identifier.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"tenant_id":      schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"hostname":       schema.StringAttribute{Required: true, Description: "Endpoint hostname."},
			"employee_name":  schema.StringAttribute{Optional: true, Description: "Employee display name tied to this endpoint."},
			"employee_email": schema.StringAttribute{Optional: true, Description: "Employee email tied to this endpoint."},
			"department":     schema.StringAttribute{Optional: true, Description: "Department label for this endpoint."},
			"os":             schema.StringAttribute{Optional: true, Description: "Operating system (macos, windows, linux)."},
			"os_version":     schema.StringAttribute{Optional: true, Description: "Operating system version."},
			"enrollment":     schema.StringAttribute{Optional: true, Description: "Enrollment source (jamf, intune, manual, unmanaged)."},
			"status":         schema.StringAttribute{Optional: true, Computed: true, Description: "Endpoint status."},
			"enforcement_mode": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enforcement mode (enforce, shadow, off).",
			},
			"environment":   schema.StringAttribute{Optional: true, Description: "Environment (dev, staging, prod)."},
			"proxy_version": schema.StringAttribute{Optional: true, Description: "Reported proxy version."},
			"agent_ids": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Agent IDs associated with this endpoint.",
			},
			"risk_score":       schema.Float64Attribute{Optional: true, Description: "Risk score for this endpoint."},
			"violations_today": schema.Int64Attribute{Optional: true, Description: "Violations seen today."},
			"sessions_today":   schema.Int64Attribute{Optional: true, Description: "Sessions seen today."},
			"fleet_id":         schema.StringAttribute{Optional: true, Description: "Fleet ID associated with this endpoint."},
			"provider_name":    schema.StringAttribute{Optional: true, Description: "Provider hint for endpoint provenance."},
			"runtime_auth_mode": schema.StringAttribute{
				Computed:    true,
				Description: "Runtime auth mode recorded by GovAPI.",
			},
			"identity_binding_user": schema.StringAttribute{
				Computed:    true,
				Description: "User identity bound to endpoint runtime credentials.",
			},
			"managed_runtime_key_id": schema.StringAttribute{
				Computed:    true,
				Description: "Server-managed runtime API key ID (when applicable).",
			},
			"last_seen":  schema.StringAttribute{Computed: true, Description: "Last heartbeat timestamp."},
			"created_at": schema.StringAttribute{Computed: true, Description: "Creation timestamp."},
			"updated_at": schema.StringAttribute{Computed: true, Description: "Last update timestamp."},
		},
	}
}

func (r *endpointResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *endpointResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan endpointResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, ok := r.upsert(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *endpointResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state endpointResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	endpointID := strings.TrimSpace(state.EndpointID.ValueString())
	if endpointID == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	row, err := r.client.GetEndpoint(ctx, endpointID)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading endpoint", err.Error())
		return
	}

	next := flattenEndpoint(row, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *endpointResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan endpointResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, ok := r.upsert(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *endpointResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// GovAPI does not currently expose endpoint delete; remove from Terraform state only.
}

func (r *endpointResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	endpointID := strings.TrimSpace(req.ID)
	if endpointID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use endpoint_id as import identifier.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), endpointID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("endpoint_id"), endpointID)...)
}

func (r *endpointResource) upsert(
	ctx context.Context,
	plan endpointResourceModel,
	diags *diag.Diagnostics,
) (endpointResourceModel, bool) {
	endpointID := strings.TrimSpace(plan.EndpointID.ValueString())
	hostname := strings.TrimSpace(plan.Hostname.ValueString())
	if endpointID == "" {
		diags.AddAttributeError(path.Root("endpoint_id"), "Missing endpoint_id", "endpoint_id must be set.")
		return endpointResourceModel{}, false
	}
	if hostname == "" {
		diags.AddAttributeError(path.Root("hostname"), "Missing hostname", "hostname must be set.")
		return endpointResourceModel{}, false
	}

	payload := map[string]any{
		"endpoint_id": endpointID,
		"hostname":    hostname,
	}
	setStringPayloadIfKnown(payload, "employee_name", plan.EmployeeName)
	setStringPayloadIfKnown(payload, "employee_email", plan.EmployeeEmail)
	setStringPayloadIfKnown(payload, "department", plan.Department)
	setStringPayloadIfKnown(payload, "os", plan.OS)
	setStringPayloadIfKnown(payload, "os_version", plan.OSVersion)
	setStringPayloadIfKnown(payload, "enrollment", plan.Enrollment)
	setStringPayloadIfKnown(payload, "status", plan.Status)
	setStringPayloadIfKnown(payload, "enforcement_mode", plan.EnforcementMode)
	setStringPayloadIfKnown(payload, "environment", plan.Environment)
	setStringPayloadIfKnown(payload, "proxy_version", plan.ProxyVersion)
	setStringPayloadIfKnown(payload, "fleet_id", plan.FleetID)
	if !plan.ProviderName.IsNull() && !plan.ProviderName.IsUnknown() {
		payload["provider"] = strings.TrimSpace(plan.ProviderName.ValueString())
	}
	if !plan.RiskScore.IsNull() && !plan.RiskScore.IsUnknown() {
		payload["risk_score"] = plan.RiskScore.ValueFloat64()
	}
	if !plan.ViolationsToday.IsNull() && !plan.ViolationsToday.IsUnknown() {
		payload["violations_today"] = plan.ViolationsToday.ValueInt64()
	}
	if !plan.SessionsToday.IsNull() && !plan.SessionsToday.IsUnknown() {
		payload["sessions_today"] = plan.SessionsToday.ValueInt64()
	}
	if !plan.AgentIDs.IsNull() && !plan.AgentIDs.IsUnknown() {
		var agentIDs []string
		diags.Append(plan.AgentIDs.ElementsAs(ctx, &agentIDs, false)...)
		if diags.HasError() {
			return endpointResourceModel{}, false
		}
		payload["agent_ids"] = agentIDs
	}

	if _, err := r.client.RegisterEndpoint(ctx, payload); err != nil {
		diags.AddError("Error registering endpoint", err.Error())
		return endpointResourceModel{}, false
	}

	row, err := r.client.GetEndpoint(ctx, endpointID)
	if err != nil {
		diags.AddError("Error reading endpoint after register", err.Error())
		return endpointResourceModel{}, false
	}
	return flattenEndpoint(row, plan, r.tenantID), true
}

func flattenEndpoint(row map[string]any, current endpointResourceModel, tenantID string) endpointResourceModel {
	next := current
	endpointID := strings.TrimSpace(tfhelpers.GetString(row, "endpoint_id"))
	next.ID = types.StringValue(endpointID)
	next.EndpointID = types.StringValue(endpointID)
	next.TenantID = types.StringValue(tenantID)
	next.Hostname = nullableString(row, "hostname")
	next.EmployeeName = nullableString(row, "employee_name")
	next.EmployeeEmail = nullableString(row, "employee_email")
	next.Department = nullableString(row, "department")
	next.OS = nullableString(row, "os")
	next.OSVersion = nullableString(row, "os_version")
	next.Enrollment = nullableString(row, "enrollment")
	next.Status = nullableString(row, "status")
	next.EnforcementMode = nullableString(row, "enforcement_mode")
	next.Environment = nullableString(row, "environment")
	next.ProxyVersion = nullableString(row, "proxy_version")
	next.AgentIDs = tfhelpers.StringSliceValue(tfhelpers.GetStringSlice(row, "agent_ids"))
	next.RiskScore = types.Float64Value(tfhelpers.GetFloat64(row, "risk_score"))
	next.ViolationsToday = types.Int64Value(tfhelpers.GetInt64(row, "violations_today"))
	next.SessionsToday = types.Int64Value(tfhelpers.GetInt64(row, "sessions_today"))
	next.FleetID = nullableString(row, "fleet_id")
	next.ProviderName = nullableString(row, "provider")
	next.RuntimeAuthMode = nullableString(row, "runtime_auth_mode")
	next.IdentityBinding = nullableString(row, "identity_binding_user")
	next.ManagedRuntimeID = nullableString(row, "managed_runtime_key_id")
	next.LastSeen = nullableString(row, "last_seen")
	next.CreatedAt = nullableString(row, "created_at")
	next.UpdatedAt = nullableString(row, "updated_at")
	return next
}

func setStringPayloadIfKnown(payload map[string]any, key string, value types.String) {
	if value.IsNull() || value.IsUnknown() {
		return
	}
	payload[key] = strings.TrimSpace(value.ValueString())
}
