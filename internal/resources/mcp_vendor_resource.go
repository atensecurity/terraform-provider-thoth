package resources

import (
	"context"
	"fmt"
	"sort"
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

var _ resource.Resource = &mcpVendorResource{}
var _ resource.ResourceWithImportState = &mcpVendorResource{}

type mcpVendorResource struct {
	client   *client.Client
	tenantID string
}

type mcpVendorModel struct {
	ID                      types.String `tfsdk:"id"`
	TenantID                types.String `tfsdk:"tenant_id"`
	VendorID                types.String `tfsdk:"vendor_id"`
	DisplayName             types.String `tfsdk:"display_name"`
	Approved                types.Bool   `tfsdk:"approved"`
	HostPatterns            types.List   `tfsdk:"host_patterns"`
	ManifestSignatureStatus types.String `tfsdk:"manifest_signature_status"`
	ManifestSignatureSigner types.String `tfsdk:"manifest_signature_signer"`
	ManifestSignatureBundle types.String `tfsdk:"manifest_signature_bundle_ref"`
	ManifestSignatureAt     types.String `tfsdk:"manifest_signature_verified_at"`
	Capabilities            types.List   `tfsdk:"capabilities"`
	RuntimeIdentity         types.String `tfsdk:"runtime_identity"`
	EgressPolicyMode        types.String `tfsdk:"egress_policy_mode"`
	EgressAllowedHosts      types.List   `tfsdk:"egress_allowed_host_patterns"`
	Source                  types.String `tfsdk:"source"`
	Notes                   types.String `tfsdk:"notes"`
	LastSeenAt              types.String `tfsdk:"last_seen_at"`
	CreatedAt               types.String `tfsdk:"created_at"`
	UpdatedAt               types.String `tfsdk:"updated_at"`
}

func NewMCPVendorResource() resource.Resource {
	return &mcpVendorResource{}
}

func (r *mcpVendorResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mcp_vendor"
}

func (r *mcpVendorResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages tenant-scoped MCP vendor registry entries used for allowlist enforcement.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource ID (vendor_id).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"tenant_id": schema.StringAttribute{
				Computed:    true,
				Description: "Tenant ID from provider configuration.",
			},
			"vendor_id": schema.StringAttribute{
				Required:      true,
				Description:   "Stable vendor identifier.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"display_name": schema.StringAttribute{
				Required:    true,
				Description: "Human-friendly vendor display name.",
			},
			"approved": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether this vendor is approved for pass-through MCP host access.",
			},
			"host_patterns": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "Allowed host patterns for this vendor (for example api.openai.com).",
			},
			"manifest_signature_status": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Manifest signature verification status (verified, pending, failed).",
			},
			"manifest_signature_signer": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Signer identity for verified manifest signatures.",
			},
			"manifest_signature_bundle_ref": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Signature bundle reference used for manifest verification.",
			},
			"manifest_signature_verified_at": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "RFC3339 timestamp when manifest signature was verified.",
			},
			"capabilities": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Capability bindings this vendor/runtime identity is allowed to request.",
			},
			"runtime_identity": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Capability-scoped runtime identity used at action-time enforcement.",
			},
			"egress_policy_mode": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Egress policy mode for vendor traffic (enforce or observe).",
			},
			"egress_allowed_host_patterns": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Allowed egress host patterns enforced for this vendor/runtime identity.",
			},
			"source": schema.StringAttribute{
				Optional:    true,
				Description: "Vendor entry source (for example manual, discovered).",
			},
			"notes": schema.StringAttribute{
				Optional:    true,
				Description: "Optional reviewer notes for this vendor entry.",
			},
			"last_seen_at": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Last observed timestamp (RFC3339) for this vendor in runtime traffic.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Creation timestamp.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Last update timestamp.",
			},
		},
	}
}

func (r *mcpVendorResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *mcpVendorResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan mcpVendorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, ok := r.createOrUpdate(ctx, plan, plan, true, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *mcpVendorResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state mcpVendorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vendorID := strings.TrimSpace(state.VendorID.ValueString())
	if vendorID == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	row, err := r.client.GetMCPVendor(ctx, vendorID)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading MCP vendor", err.Error())
		return
	}

	next := flattenMCPVendor(ctx, row, state, r.tenantID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *mcpVendorResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan mcpVendorModel
	var state mcpVendorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	next, ok := r.createOrUpdate(ctx, plan, state, false, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *mcpVendorResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state mcpVendorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vendorID := strings.TrimSpace(state.VendorID.ValueString())
	if vendorID == "" {
		return
	}
	if err := r.client.DeleteMCPVendor(ctx, vendorID); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddWarning("Failed to delete MCP vendor", err.Error())
	}
}

func (r *mcpVendorResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	vendorID := parseMCPVendorImportID(req.ID)
	if vendorID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use vendor_id or tenant_id/vendor_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), vendorID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vendor_id"), vendorID)...)
}

func parseMCPVendorImportID(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "/")
	return strings.TrimSpace(parts[len(parts)-1])
}

func (r *mcpVendorResource) createOrUpdate(
	ctx context.Context,
	plan, prior mcpVendorModel,
	isCreate bool,
	diags *diag.Diagnostics,
) (mcpVendorModel, bool) {
	vendorID := strings.TrimSpace(plan.VendorID.ValueString())
	displayName := strings.TrimSpace(plan.DisplayName.ValueString())
	if vendorID == "" {
		diags.AddAttributeError(path.Root("vendor_id"), "Missing vendor_id", "vendor_id must be set.")
		return mcpVendorModel{}, false
	}
	if displayName == "" {
		diags.AddAttributeError(path.Root("display_name"), "Missing display_name", "display_name must be set.")
		return mcpVendorModel{}, false
	}

	var hostPatterns []string
	diags.Append(plan.HostPatterns.ElementsAs(ctx, &hostPatterns, false)...)
	if diags.HasError() {
		return mcpVendorModel{}, false
	}
	if len(hostPatterns) == 0 {
		diags.AddAttributeError(path.Root("host_patterns"), "Missing host_patterns", "host_patterns must include at least one host pattern.")
		return mcpVendorModel{}, false
	}

	payload := map[string]any{
		"vendor_id":     vendorID,
		"display_name":  displayName,
		"host_patterns": hostPatterns,
		"approved":      false,
	}

	if !plan.Approved.IsNull() && !plan.Approved.IsUnknown() {
		payload["approved"] = plan.Approved.ValueBool()
	} else if !isCreate && !prior.Approved.IsNull() && !prior.Approved.IsUnknown() {
		payload["approved"] = prior.Approved.ValueBool()
	}
	setStringIfKnown(payload, "source", plan.Source, prior.Source)
	setStringIfKnown(payload, "notes", plan.Notes, prior.Notes)
	setStringIfKnown(payload, "last_seen_at", plan.LastSeenAt, prior.LastSeenAt)

	manifestStatus := resolveOptionalString(plan.ManifestSignatureStatus, prior.ManifestSignatureStatus)
	manifestSigner := resolveOptionalString(plan.ManifestSignatureSigner, prior.ManifestSignatureSigner)
	manifestBundleRef := resolveOptionalString(plan.ManifestSignatureBundle, prior.ManifestSignatureBundle)
	manifestVerifiedAt := resolveOptionalString(plan.ManifestSignatureAt, prior.ManifestSignatureAt)
	if manifestStatus != "" || manifestSigner != "" || manifestBundleRef != "" || manifestVerifiedAt != "" {
		manifest := map[string]any{}
		if manifestStatus != "" {
			manifest["status"] = manifestStatus
		}
		if manifestSigner != "" {
			manifest["signer"] = manifestSigner
		}
		if manifestBundleRef != "" {
			manifest["bundle_ref"] = manifestBundleRef
		}
		if manifestVerifiedAt != "" {
			manifest["verified_at"] = manifestVerifiedAt
		}
		payload["manifest_signature"] = manifest
	}

	capabilities := resolveOptionalStringList(ctx, plan.Capabilities, prior.Capabilities, diags)
	if diags.HasError() {
		return mcpVendorModel{}, false
	}
	if capabilities != nil {
		payload["capabilities"] = capabilities
	}

	runtimeIdentity := resolveOptionalString(plan.RuntimeIdentity, prior.RuntimeIdentity)
	if runtimeIdentity != "" {
		payload["runtime_identity"] = runtimeIdentity
	}

	egressMode := resolveOptionalString(plan.EgressPolicyMode, prior.EgressPolicyMode)
	egressHosts := resolveOptionalStringList(ctx, plan.EgressAllowedHosts, prior.EgressAllowedHosts, diags)
	if diags.HasError() {
		return mcpVendorModel{}, false
	}
	if egressMode != "" || egressHosts != nil {
		egressPolicy := map[string]any{}
		if egressMode != "" {
			egressPolicy["mode"] = egressMode
		}
		if egressHosts != nil {
			egressPolicy["allowed_host_patterns"] = egressHosts
		}
		payload["egress_policy"] = egressPolicy
	}

	var (
		row map[string]any
		err error
	)
	if isCreate {
		row, err = r.client.CreateMCPVendor(ctx, payload)
	} else {
		row, err = r.client.UpdateMCPVendor(ctx, vendorID, payload)
	}
	if err != nil {
		action := "creating"
		if !isCreate {
			action = "updating"
		}
		diags.AddError(
			fmt.Sprintf("Error %s MCP vendor", action),
			err.Error(),
		)
		return mcpVendorModel{}, false
	}

	return flattenMCPVendor(ctx, row, plan, r.tenantID), true
}

func flattenMCPVendor(ctx context.Context, row map[string]any, current mcpVendorModel, tenantID string) mcpVendorModel {
	next := current
	next.ID = types.StringValue(strings.TrimSpace(tfhelpers.GetString(row, "vendor_id")))
	next.TenantID = types.StringValue(tenantID)
	next.VendorID = types.StringValue(strings.TrimSpace(tfhelpers.GetString(row, "vendor_id")))
	next.DisplayName = types.StringValue(strings.TrimSpace(tfhelpers.GetString(row, "display_name")))
	next.Approved = types.BoolValue(tfhelpers.GetBool(row, "approved"))

	apiHostPatterns := normalizeHostPatterns(tfhelpers.GetStringSlice(row, "host_patterns"))

	currentHostPatterns := []string{}
	if !current.HostPatterns.IsNull() && !current.HostPatterns.IsUnknown() {
		_ = current.HostPatterns.ElementsAs(ctx, &currentHostPatterns, false)
		currentHostPatterns = normalizeHostPatterns(currentHostPatterns)
	}

	resolvedHostPatterns := apiHostPatterns
	if len(currentHostPatterns) > 0 && sameStringSet(currentHostPatterns, apiHostPatterns) {
		// Preserve operator-declared order when API response only differs by ordering.
		resolvedHostPatterns = currentHostPatterns
	} else {
		// Keep ordering deterministic for drift-free refreshes.
		resolvedHostPatterns = append([]string(nil), apiHostPatterns...)
		sort.Strings(resolvedHostPatterns)
	}
	next.HostPatterns = tfhelpers.StringSliceValue(resolvedHostPatterns)

	manifest := tfhelpers.GetMap(row, "manifest_signature")
	next.ManifestSignatureStatus = nullableString(manifest, "status")
	next.ManifestSignatureSigner = nullableString(manifest, "signer")
	next.ManifestSignatureBundle = nullableString(manifest, "bundle_ref")
	next.ManifestSignatureAt = nullableString(manifest, "verified_at")

	next.Capabilities = nullableStringSlice(row, "capabilities")
	next.RuntimeIdentity = nullableString(row, "runtime_identity")

	egressPolicy := tfhelpers.GetMap(row, "egress_policy")
	next.EgressPolicyMode = nullableString(egressPolicy, "mode")
	next.EgressAllowedHosts = nullableStringSlice(egressPolicy, "allowed_host_patterns")

	next.Source = nullableString(row, "source")
	next.Notes = nullableString(row, "notes")
	next.LastSeenAt = nullableString(row, "last_seen_at")
	next.CreatedAt = nullableString(row, "created_at")
	next.UpdatedAt = nullableString(row, "updated_at")
	return next
}

func normalizeHostPatterns(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	counts := make(map[string]int, len(a))
	for _, value := range a {
		counts[value]++
	}
	for _, value := range b {
		count, ok := counts[value]
		if !ok || count == 0 {
			return false
		}
		counts[value]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func resolveOptionalString(value, fallback types.String) string {
	if !value.IsNull() && !value.IsUnknown() {
		return strings.TrimSpace(value.ValueString())
	}
	if !fallback.IsNull() && !fallback.IsUnknown() {
		return strings.TrimSpace(fallback.ValueString())
	}
	return ""
}

func resolveOptionalStringList(ctx context.Context, value, fallback types.List, diags *diag.Diagnostics) []string {
	if !value.IsNull() && !value.IsUnknown() {
		items := decodeStringList(ctx, value, diags)
		if diags.HasError() {
			return nil
		}
		return items
	}
	if !fallback.IsNull() && !fallback.IsUnknown() {
		items := decodeStringList(ctx, fallback, diags)
		if diags.HasError() {
			return nil
		}
		return items
	}
	return nil
}

func decodeStringList(ctx context.Context, value types.List, diags *diag.Diagnostics) []string {
	items := []string{}
	diags.Append(value.ElementsAs(ctx, &items, false)...)
	if diags.HasError() {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func nullableStringSlice(m map[string]any, key string) types.List {
	raw, ok := m[key]
	if !ok || raw == nil {
		return types.ListNull(types.StringType)
	}
	values := normalizeHostPatterns(tfhelpers.GetStringSlice(m, key))
	if len(values) == 0 {
		return tfhelpers.StringSliceValue([]string{})
	}
	return tfhelpers.StringSliceValue(values)
}
