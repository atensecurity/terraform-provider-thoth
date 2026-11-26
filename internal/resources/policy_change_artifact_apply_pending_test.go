package resources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

// An apply whose bundle publish was held for approval answers 202 with
// apply_pending. The resource must fail and write no state, or Terraform would
// record a policy change that is not in force.
func TestPolicyChangeArtifactApplyCreateIsPendingNotApplied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"request_id":"req-1","apply_pending":true,"change_id":"c9","message":"approve it"}`))
	}))
	defer srv.Close()
	c, err := client.New(client.Config{BaseURL: srv.URL, TenantID: "example-tenant", AuthToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	r := &policyChangeArtifactApplyResource{client: c, tenantID: "example-tenant"}

	ctx := context.Background()
	var sch resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sch)
	objType := sch.Schema.Type().TerraformType(ctx).(tftypes.Object)
	values := map[string]tftypes.Value{}
	for name, typ := range objType.AttributeTypes {
		values[name] = tftypes.NewValue(typ, nil)
	}
	values["request_id"] = tftypes.NewValue(tftypes.String, "req-1")
	values["applied_by"] = tftypes.NewValue(tftypes.String, "admin")
	raw := tftypes.NewValue(objType, values)

	req := resource.CreateRequest{Plan: tfsdk.Plan{Schema: sch.Schema, Raw: raw}}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: sch.Schema, Raw: tftypes.NewValue(objType, nil)}}
	r.Create(ctx, req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("a held apply must be an error, not an applied change")
	}
	if !strings.Contains(resp.Diagnostics.Errors()[0].Summary(), "pending approval") {
		t.Fatalf("summary = %q", resp.Diagnostics.Errors()[0].Summary())
	}
	if !resp.State.Raw.IsNull() {
		t.Fatal("state was written for a change that is not in force")
	}
}
