package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &modelArtifactResource{}
var _ resource.ResourceWithImportState = &modelArtifactResource{}
var _ resource.ResourceWithModifyPlan = &modelArtifactResource{}

type modelArtifactResource struct {
	client   *client.Client
	tenantID string
}

type modelArtifactModel struct {
	ID                types.String `tfsdk:"id"`
	ArtifactID        types.String `tfsdk:"artifact_id"`
	ModelName         types.String `tfsdk:"model_name"`
	ModelProvider     types.String `tfsdk:"model_provider"`
	ArtifactURI       types.String `tfsdk:"artifact_uri"`
	Version           types.String `tfsdk:"version"`
	DigestSHA256      types.String `tfsdk:"digest_sha256"`
	SigningStatus     types.String `tfsdk:"signing_status"`
	ProvenanceProfile types.String `tfsdk:"provenance_profile"`
	Provenance        types.Object `tfsdk:"provenance"`
	Screening         types.Object `tfsdk:"screening"`
	WaiverReason      types.String `tfsdk:"waiver_reason"`
	Activate          types.Bool   `tfsdk:"activate"`
	LifecycleStatus   types.String `tfsdk:"lifecycle_status"`
	ScreeningStatus   types.String `tfsdk:"screening_status"`
	ProvenanceStatus  types.String `tfsdk:"provenance_status"`
	ProvenanceError   types.String `tfsdk:"provenance_error"`
	ActivatedAt       types.String `tfsdk:"activated_at"`
	CreatedAt         types.String `tfsdk:"created_at"`
}

type modelArtifactProvenance struct {
	VerificationMode      types.String `tfsdk:"verification_mode"`
	ManualStatus          types.String `tfsdk:"manual_status"`
	CertificateIdentity   types.String `tfsdk:"certificate_identity"`
	CertificateOIDCIssuer types.String `tfsdk:"certificate_oidc_issuer"`
	TransparencyLogURI    types.String `tfsdk:"transparency_log_uri"`
	SignatureBundleRef    types.String `tfsdk:"signature_bundle_ref"`
	InTotoAttestationRef  types.String `tfsdk:"intoto_attestation_ref"`
	PublicKeyRef          types.String `tfsdk:"public_key_ref"`
	EvidenceRef           types.String `tfsdk:"evidence_ref"`
}

type modelArtifactScreening struct {
	Status types.String `tfsdk:"status"`
	Tool   types.String `tfsdk:"tool"`
	Notes  types.String `tfsdk:"notes"`
}

func NewModelArtifactResource() resource.Resource {
	return &modelArtifactResource{}
}

func (r *modelArtifactResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_model_artifact"
}

func replaceString(description string, required bool) schema.StringAttribute {
	return schema.StringAttribute{
		Required:      required,
		Optional:      !required,
		Description:   description,
		PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
	}
}

func (r *modelArtifactResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	optional := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Optional: true, Description: description}
	}
	computed := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, Description: description}
	}
	resp.Schema = schema.Schema{
		Description: "A model artifact in Thoth's registry, and how far it is through the activation gate: provenance " +
			"verification, then screening (or a waiver), then activation. Registration fields cannot change; changing one " +
			"registers a new artifact. Activation and waivers cannot be undone. Thoth keeps every artifact and its " +
			"activation evidence, so destroying this resource only removes it from Terraform state.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "The artifact ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"artifact_id": schema.StringAttribute{
				Optional: true, Computed: true,
				Description: "Artifact ID. Generated when unset. A registered ID cannot be reused.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"model_name":     replaceString("Model name.", true),
			"model_provider": replaceString("Model provider, such as openai or huggingface.", true),
			"artifact_uri":   replaceString("Where the artifact is stored.", true),
			"version":        replaceString("Artifact version.", false),
			"digest_sha256":  replaceString("SHA-256 digest of the artifact. Provenance evidence must name it.", false),
			"signing_status": replaceString("Signing status at registration, such as signed or unsigned. Thoth sets it to verified when provenance verifies.", false),
			"provenance_profile": func() schema.StringAttribute {
				a := replaceString("connected (Sigstore keyless, the default) or sovereign (tenant-managed keys, no public transparency log).", false)
				a.Validators = []validator.String{stringvalidator.OneOf("connected", "sovereign")}
				return a
			}(),
			"provenance": schema.SingleNestedAttribute{
				Optional: true,
				Description: "Provenance verification, run on create and whenever this block changes. Thoth checks the evidence " +
					"against the profile and its allowlists, and checks signatures cryptographically only when the workspace has " +
					"signature verification turned on. A failed verification marks the artifact rejected.",
				Attributes: map[string]schema.Attribute{
					"verification_mode": schema.StringAttribute{
						Optional:    true,
						Description: "sigstore_keyless (connected), tenant_managed_keys (sovereign) or manual. Defaults to the profile's mode.",
						Validators:  []validator.String{stringvalidator.OneOf("sigstore_keyless", "tenant_managed_keys", "manual")},
					},
					"manual_status": schema.StringAttribute{
						Optional: true,
						Description: "With verification_mode = \"manual\": the status an admin attests (verified, failed, revoked or pending). " +
							"Recorded as a manual attestation, not a verification by Thoth.",
						Validators: []validator.String{stringvalidator.OneOf("verified", "failed", "revoked", "pending")},
					},
					"certificate_identity":    optional("Signing certificate identity (connected profile)."),
					"certificate_oidc_issuer": optional("Signing certificate OIDC issuer (connected profile)."),
					"transparency_log_uri":    optional("Transparency log entry URI."),
					"signature_bundle_ref":    optional("Signature bundle reference."),
					"intoto_attestation_ref":  optional("in-toto attestation reference."),
					"public_key_ref":          optional("Public key reference (sovereign profile)."),
					"evidence_ref":            optional("Other evidence reference."),
				},
			},
			"screening": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Screening result, recorded on create and whenever this block changes.",
				Attributes: map[string]schema.Attribute{
					"status": schema.StringAttribute{
						Required:    true,
						Description: "passed, failed or pending.",
						Validators:  []validator.String{stringvalidator.OneOf("passed", "failed", "pending")},
					},
					"tool":  optional("The screening tool."),
					"notes": optional("Screening notes."),
				},
			},
			"waiver_reason": schema.StringAttribute{
				Optional:    true,
				Description: "Waive screening, with this reason. A waiver cannot be withdrawn.",
			},
			"activate": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "Activate the artifact. Needs verified provenance and a passed screening or a waiver. Cannot be undone.",
			},
			"lifecycle_status":  computed("registered, screened, waived, active or rejected."),
			"screening_status":  computed("pending, passed or failed."),
			"provenance_status": computed("pending, verified, failed or revoked."),
			"provenance_error":  computed("Why provenance verification failed, when it did."),
			"activated_at":      computed("When the artifact was activated."),
			"created_at":        computed("When the artifact was registered."),
		},
	}
}

func (r *modelArtifactResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

// ModifyPlan refuses, at plan time, the changes GovAPI cannot make.
func (r *modelArtifactResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var state, plan modelArtifactModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(modelArtifactIrreversible(state, plan)...)
}

func modelArtifactIrreversible(state, plan modelArtifactModel) diag.Diagnostics {
	var diags diag.Diagnostics
	if state.Activate.ValueBool() && !plan.Activate.ValueBool() {
		diags.AddAttributeError(path.Root("activate"), "Activation cannot be undone",
			"Thoth has no way to deactivate an artifact. Keep activate = true, or register a new artifact.")
	}
	if knownString(state.WaiverReason) && !knownString(plan.WaiverReason) {
		diags.AddAttributeError(path.Root("waiver_reason"), "A waiver cannot be withdrawn",
			"Thoth keeps the waiver on the artifact. Keep waiver_reason, or register a new artifact.")
	}
	return diags
}

func knownString(v types.String) bool { return !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" }

func (r *modelArtifactResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan modelArtifactModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := map[string]any{
		"model_name":     plan.ModelName.ValueString(),
		"model_provider": plan.ModelProvider.ValueString(),
		"artifact_uri":   plan.ArtifactURI.ValueString(),
	}
	for key, value := range map[string]types.String{
		"artifact_id": plan.ArtifactID, "version": plan.Version, "digest_sha256": plan.DigestSHA256,
		"signing_status": plan.SigningStatus, "provenance_profile": plan.ProvenanceProfile,
	} {
		if knownString(value) {
			payload[key] = value.ValueString()
		}
	}
	created, err := r.client.CreateModelArtifact(ctx, payload)
	if err != nil {
		detail := err.Error()
		if strings.Contains(detail, "already exists") {
			detail += "\n\nRegistered artifacts cannot change. Give the new artifact a different artifact_id."
		}
		resp.Diagnostics.AddError("Error registering model artifact", detail)
		return
	}
	plan.ArtifactID = types.StringValue(tfhelpers.GetString(created, "artifact_id"))
	plan.ID = plan.ArtifactID
	// The artifact exists from here on; record it even if a later step fails.
	r.runSteps(ctx, plan, nil, created, &resp.Diagnostics, func(next modelArtifactModel) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
	})
}

func (r *modelArtifactResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state modelArtifactModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(modelArtifactIrreversible(state, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ArtifactID, plan.ID = state.ArtifactID, state.ID
	current, err := r.client.GetModelArtifact(ctx, state.ArtifactID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading model artifact", err.Error())
		return
	}
	r.runSteps(ctx, plan, &state, current, &resp.Diagnostics, func(next modelArtifactModel) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
	})
}

// runSteps applies the lifecycle steps whose configuration changed, in the
// order the activation gate needs them, then records the artifact's state.
// save runs even when a step fails, so state matches what GovAPI holds.
func (r *modelArtifactResource) runSteps(ctx context.Context, plan modelArtifactModel, prior *modelArtifactModel, current map[string]any, diags *diag.Diagnostics, save func(modelArtifactModel)) {
	id := plan.ArtifactID.ValueString()
	changed := func(planValue, priorValue attr.Value) bool {
		return prior == nil || !planValue.Equal(priorValue)
	}
	defer func() {
		latest, err := r.client.GetModelArtifact(ctx, id)
		if err != nil {
			diags.AddError("Error reading model artifact", err.Error())
			latest = current
		}
		save(flattenModelArtifact(plan, latest))
	}()

	if !plan.Provenance.IsNull() && changed(plan.Provenance, priorOr(prior, func(m modelArtifactModel) attr.Value { return m.Provenance })) {
		var p modelArtifactProvenance
		diags.Append(plan.Provenance.As(ctx, &p, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return
		}
		out, err := r.client.VerifyModelArtifactProvenance(ctx, id, provenancePayload(p, plan.ProvenanceProfile))
		if err != nil {
			diags.AddError("Error verifying model artifact provenance", err.Error())
			return
		}
		if status := tfhelpers.GetString(tfhelpers.GetMap(out, "provenance_verification"), "status"); status != "verified" {
			diags.AddWarning("Provenance is not verified",
				fmt.Sprintf("Thoth recorded provenance as %q: %s", status, tfhelpers.GetString(tfhelpers.GetMap(out, "provenance_verification"), "error_message")))
		}
	}
	if !plan.Screening.IsNull() && changed(plan.Screening, priorOr(prior, func(m modelArtifactModel) attr.Value { return m.Screening })) {
		var s modelArtifactScreening
		diags.Append(plan.Screening.As(ctx, &s, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return
		}
		payload := map[string]any{"screening_status": s.Status.ValueString()}
		if knownString(s.Tool) {
			payload["screening_tool"] = s.Tool.ValueString()
		}
		if knownString(s.Notes) {
			payload["screening_notes"] = s.Notes.ValueString()
		}
		if _, err := r.client.ScreenModelArtifact(ctx, id, payload); err != nil {
			diags.AddError("Error recording model artifact screening", err.Error())
			return
		}
	}
	if knownString(plan.WaiverReason) && changed(plan.WaiverReason, priorOr(prior, func(m modelArtifactModel) attr.Value { return m.WaiverReason })) {
		if _, err := r.client.WaiveModelArtifact(ctx, id, plan.WaiverReason.ValueString()); err != nil {
			diags.AddError("Error waiving model artifact screening", err.Error())
			return
		}
	}
	if !plan.Activate.ValueBool() {
		return
	}
	// Read the status after the steps above: a new screening moves an active
	// artifact back to screened, and then it needs activating again.
	latest, err := r.client.GetModelArtifact(ctx, id)
	if err != nil {
		diags.AddError("Error reading model artifact", err.Error())
		return
	}
	if tfhelpers.GetString(latest, "lifecycle_status") != "active" {
		if _, err := r.client.ActivateModelArtifact(ctx, id); err != nil {
			diags.AddError("Error activating model artifact", err.Error())
			return
		}
	}
}

func priorOr(prior *modelArtifactModel, get func(modelArtifactModel) attr.Value) attr.Value {
	if prior == nil {
		return nil
	}
	return get(*prior)
}

func provenancePayload(p modelArtifactProvenance, profile types.String) map[string]any {
	payload := map[string]any{}
	if knownString(profile) {
		payload["profile"] = profile.ValueString()
	}
	for key, value := range map[string]types.String{
		"verification_mode": p.VerificationMode, "status": p.ManualStatus,
		"certificate_identity": p.CertificateIdentity, "certificate_oidc_issuer": p.CertificateOIDCIssuer,
		"transparency_log_uri": p.TransparencyLogURI, "signature_bundle_ref": p.SignatureBundleRef,
		"intoto_attestation_ref": p.InTotoAttestationRef, "public_key_ref": p.PublicKeyRef, "evidence_ref": p.EvidenceRef,
	} {
		if knownString(value) {
			payload[key] = value.ValueString()
		}
	}
	return payload
}

func (r *modelArtifactResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state modelArtifactModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetModelArtifact(ctx, state.ArtifactID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading model artifact", err.Error())
		return
	}
	next := flattenModelArtifact(state, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

// Delete removes the artifact from state only: GovAPI keeps the registry
// record and its activation evidence.
func (r *modelArtifactResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning("Model artifact kept in Thoth",
		"Thoth keeps registered artifacts and their activation evidence. The artifact was removed from Terraform state only.")
}

func (r *modelArtifactResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use the artifact ID as the import identifier.")
		return
	}
	out, err := r.client.GetModelArtifact(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Error reading model artifact", err.Error())
		return
	}
	// Registration fields come from the registry; lifecycle steps are not
	// replayed, so their blocks start empty.
	imported := modelArtifactModel{
		ArtifactID:        types.StringValue(id),
		ModelName:         stringValueFromMap(out, "model_name"),
		ModelProvider:     stringValueFromMap(out, "model_provider"),
		ArtifactURI:       stringValueFromMap(out, "artifact_uri"),
		Version:           stringValueFromMap(out, "version"),
		DigestSHA256:      stringValueFromMap(out, "digest_sha256"),
		SigningStatus:     types.StringNull(),
		ProvenanceProfile: stringValueFromMap(tfhelpers.GetMap(out, "provenance_verification"), "profile"),
		Provenance:        types.ObjectNull(provenanceAttrTypes()),
		Screening:         types.ObjectNull(screeningAttrTypes()),
		WaiverReason:      stringValueFromMap(tfhelpers.GetMap(out, "waiver"), "reason"),
		Activate:          types.BoolValue(tfhelpers.GetString(out, "lifecycle_status") == "active"),
	}
	next := flattenModelArtifact(imported, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func provenanceAttrTypes() map[string]attr.Type {
	out := map[string]attr.Type{}
	for _, key := range []string{"verification_mode", "manual_status", "certificate_identity", "certificate_oidc_issuer",
		"transparency_log_uri", "signature_bundle_ref", "intoto_attestation_ref", "public_key_ref", "evidence_ref"} {
		out[key] = types.StringType
	}
	return out
}

func screeningAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{"status": types.StringType, "tool": types.StringType, "notes": types.StringType}
}

// flattenModelArtifact keeps the configured inputs and reads the lifecycle
// outputs from GovAPI's record.
func flattenModelArtifact(current modelArtifactModel, out map[string]any) modelArtifactModel {
	state := current
	if id := tfhelpers.GetString(out, "artifact_id"); id != "" {
		state.ArtifactID = types.StringValue(id)
	}
	state.ID = state.ArtifactID
	provenance := tfhelpers.GetMap(out, "provenance_verification")
	state.LifecycleStatus = stringValueFromMap(out, "lifecycle_status")
	state.ScreeningStatus = stringValueFromMap(out, "screening_status")
	state.ProvenanceStatus = stringValueFromMap(provenance, "status")
	state.ProvenanceError = stringValueFromMap(provenance, "error_message")
	state.ActivatedAt = stringValueFromMap(out, "activated_at")
	state.CreatedAt = stringValueFromMap(out, "created_at")
	// activate reflects whether Thoth holds the artifact active, so an artifact
	// that stopped being active (a new screening, a failed verification) shows
	// as a change in the next plan.
	state.Activate = types.BoolValue(tfhelpers.GetString(out, "lifecycle_status") == "active")
	return state
}
