package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

// modelArtifactAPI applies GovAPI's lifecycle rules to one artifact.
type modelArtifactAPI struct {
	mu        sync.Mutex
	artifact  map[string]any
	calls     []string
	verifyGet string // provenance status a verification records
}

func (a *modelArtifactAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		body := map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		rest := strings.TrimPrefix(r.URL.Path, "/tenant-a/thoth/model-artifacts")
		a.calls = append(a.calls, r.Method+" "+rest)
		write := func(code int, v any) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		switch {
		case r.Method == http.MethodPost && rest == "":
			if a.artifact != nil {
				write(http.StatusConflict, map[string]any{"error": "conflict", "message": "Model artifact already exists"})
				return
			}
			id, _ := body["artifact_id"].(string)
			if id == "" {
				id = "model_artifact_generated"
			}
			a.artifact = map[string]any{
				"artifact_id": id, "model_name": body["model_name"], "lifecycle_status": "registered",
				"screening_status": "pending", "created_at": "2026-10-27T10:00:00Z",
				"provenance_verification": map[string]any{"status": "pending", "profile": "connected"},
				"waiver":                  map[string]any{"approved": false},
			}
		case a.artifact == nil:
			write(http.StatusNotFound, map[string]any{"error": "not_found", "message": "Model artifact not found"})
			return
		case strings.HasSuffix(rest, "/provenance/verify"):
			status := a.verifyGet
			if status == "" {
				status = "verified"
			}
			a.artifact["provenance_verification"] = map[string]any{"status": status, "error_message": map[bool]string{true: "", false: "signature_bundle_ref is required"}[status == "verified"]}
			if status == "failed" {
				a.artifact["lifecycle_status"] = "rejected"
			}
		case strings.HasSuffix(rest, "/screen"):
			a.artifact["screening_status"] = body["screening_status"]
			a.artifact["lifecycle_status"] = map[bool]string{true: "screened", false: "rejected"}[body["screening_status"] == "passed"]
		case strings.HasSuffix(rest, "/waive"):
			a.artifact["waiver"] = map[string]any{"approved": true, "reason": body["reason"]}
			a.artifact["lifecycle_status"] = "waived"
		case strings.HasSuffix(rest, "/activate"):
			verified := a.artifact["provenance_verification"].(map[string]any)["status"] == "verified"
			waived := a.artifact["waiver"].(map[string]any)["approved"] == true
			if !verified {
				write(http.StatusConflict, map[string]any{"error": "invalid_state", "message": "Model artifact provenance must be verified before activation"})
				return
			}
			if a.artifact["screening_status"] != "passed" && !waived {
				write(http.StatusConflict, map[string]any{"error": "invalid_state", "message": "Model artifact must be screened passed or waived before activation"})
				return
			}
			a.artifact["lifecycle_status"], a.artifact["activated_at"] = "active", "2026-10-27T10:05:00Z"
		}
		write(http.StatusOK, a.artifact)
	})
}

func newModelArtifactResource(t *testing.T, api *modelArtifactAPI) *modelArtifactResource {
	t.Helper()
	server := httptest.NewServer(api.handler(t))
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	return &modelArtifactResource{client: c, tenantID: "tenant-a"}
}

func artifactPlan(screening string, activate bool) modelArtifactModel {
	provenance := map[string]attr.Value{}
	for key := range provenanceAttrTypes() {
		provenance[key] = types.StringNull()
	}
	provenance["verification_mode"] = types.StringValue("sigstore_keyless")
	provenance["signature_bundle_ref"] = types.StringValue("oci://registry/model.sig")
	plan := modelArtifactModel{
		ArtifactID:        types.StringValue("ma_1"),
		ModelName:         types.StringValue("fraud-scorer"),
		ModelProvider:     types.StringValue("huggingface"),
		ArtifactURI:       types.StringValue("hf://acme/fraud-scorer"),
		ProvenanceProfile: types.StringNull(),
		Provenance:        types.ObjectValueMust(provenanceAttrTypes(), provenance),
		Screening:         types.ObjectNull(screeningAttrTypes()),
		WaiverReason:      types.StringNull(),
		Activate:          types.BoolValue(activate),
	}
	if screening != "" {
		plan.Screening = types.ObjectValueMust(screeningAttrTypes(), map[string]attr.Value{
			"status": types.StringValue(screening), "tool": types.StringValue("modelscan"), "notes": types.StringNull(),
		})
	}
	return plan
}

// apply runs the resource's lifecycle steps as Create (prior nil) or Update.
func (r *modelArtifactResource) applyForTest(t *testing.T, plan modelArtifactModel, prior *modelArtifactModel) (modelArtifactModel, diag.Diagnostics) {
	t.Helper()
	var diags diag.Diagnostics
	ctx := context.Background()
	current := map[string]any{}
	if prior == nil {
		created, err := r.client.CreateModelArtifact(ctx, map[string]any{"artifact_id": plan.ArtifactID.ValueString(), "model_name": plan.ModelName.ValueString()})
		if err != nil {
			diags.AddError("create", err.Error())
			return plan, diags
		}
		current = created
	} else {
		current, _ = r.client.GetModelArtifact(ctx, plan.ArtifactID.ValueString())
	}
	var saved modelArtifactModel
	r.runSteps(ctx, plan, prior, current, &diags, func(next modelArtifactModel) { saved = next })
	return saved, diags
}

func TestModelArtifactRunsTheActivationGateInOrder(t *testing.T) {
	api := &modelArtifactAPI{}
	r := newModelArtifactResource(t, api)
	state, diags := r.applyForTest(t, artifactPlan("passed", true), nil)
	if diags.HasError() {
		t.Fatalf("apply: %v", diags)
	}
	want := []string{"POST ", "POST /ma_1/provenance/verify", "POST /ma_1/screen", "GET /ma_1", "POST /ma_1/activate", "GET /ma_1"}
	if strings.Join(api.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls %v, want %v", api.calls, want)
	}
	if state.LifecycleStatus.ValueString() != "active" || !state.Activate.ValueBool() || state.ProvenanceStatus.ValueString() != "verified" {
		t.Fatalf("state %+v", state)
	}

	// An unchanged plan runs nothing but reads.
	api.calls = nil
	if _, diags := r.applyForTest(t, artifactPlan("passed", true), &state); diags.HasError() {
		t.Fatalf("reapply: %v", diags)
	}
	for _, call := range api.calls {
		if strings.HasPrefix(call, "POST") {
			t.Fatalf("unchanged plan posted %s", call)
		}
	}
}

func TestModelArtifactRescreeningReactivates(t *testing.T) {
	api := &modelArtifactAPI{}
	r := newModelArtifactResource(t, api)
	state, _ := r.applyForTest(t, artifactPlan("passed", true), nil)
	plan := artifactPlan("passed", true)
	plan.Screening = types.ObjectValueMust(screeningAttrTypes(), map[string]attr.Value{
		"status": types.StringValue("passed"), "tool": types.StringValue("modelscan"), "notes": types.StringValue("rescanned v2"),
	})
	next, diags := r.applyForTest(t, plan, &state)
	if diags.HasError() {
		t.Fatalf("apply: %v", diags)
	}
	if next.LifecycleStatus.ValueString() != "active" {
		t.Fatalf("a new screening must not leave the artifact inactive: %+v", next)
	}
}

func TestModelArtifactReportsTheGateThatFailed(t *testing.T) {
	api := &modelArtifactAPI{verifyGet: "failed"}
	r := newModelArtifactResource(t, api)
	state, diags := r.applyForTest(t, artifactPlan("passed", true), nil)
	if !diags.HasError() || !strings.Contains(diags.Errors()[0].Detail(), "provenance must be verified") {
		t.Fatalf("diags %v", diags)
	}
	if len(diags.Warnings()) == 0 || !strings.Contains(diags.Warnings()[0].Detail(), "signature_bundle_ref is required") {
		t.Fatalf("the verification failure is explained: %v", diags.Warnings())
	}
	if state.Activate.ValueBool() || state.ArtifactID.ValueString() != "ma_1" {
		t.Fatalf("state records the registered, inactive artifact: %+v", state)
	}
}

func TestModelArtifactRefusesIrreversibleChanges(t *testing.T) {
	active := artifactPlan("passed", true)
	active.WaiverReason = types.StringValue("vendor attested")
	inactive := artifactPlan("passed", false)
	diags := modelArtifactIrreversible(active, inactive)
	if len(diags.Errors()) != 2 {
		t.Fatalf("want activation and waiver refusals, got %v", diags)
	}
	if modelArtifactIrreversible(inactive, active).HasError() {
		t.Fatal("activating and waiving are allowed")
	}
}

func TestModelArtifactCreateExplainsAReusedID(t *testing.T) {
	api := &modelArtifactAPI{artifact: map[string]any{"artifact_id": "ma_1"}}
	r := newModelArtifactResource(t, api)
	_, err := r.client.CreateModelArtifact(context.Background(), map[string]any{"artifact_id": "ma_1"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err %v", err)
	}
}
