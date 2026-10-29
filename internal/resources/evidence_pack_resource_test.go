package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
)

// evidencePackAPI applies GovAPI's queue rules: one queued or building pack
// per workspace, a 409 carrying it, and a build that finishes after polls.
type evidencePackAPI struct {
	mu        sync.Mutex
	packs     []map[string]any
	posts     int
	listsLeft int    // lists before the active pack finishes
	finishAs  string // ready or failed
}

func (a *evidencePackAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		write := func(code int, v any) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		if r.URL.Path != "/tenant-a/thoth/evidence/packs" {
			write(http.StatusNotFound, map[string]any{"message": "not found"})
			return
		}
		if r.Method == http.MethodGet {
			if a.listsLeft--; a.listsLeft == 0 {
				for _, p := range a.packs {
					if p["status"] == "queued" || p["status"] == "building" {
						p["status"] = a.finishAs
						p["completed_at"] = "2026-10-29T12:05:00Z"
						if a.finishAs == "ready" {
							p["parts"] = []any{map[string]any{"part": 1, "final": true, "key": "packs/p/1.zip"}}
							p["totals"] = map[string]any{"attestations": 3, "chain_events": 9}
						} else {
							p["error"] = "signing key unavailable"
						}
					}
				}
			}
			out := make([]any, 0, len(a.packs))
			for i := len(a.packs) - 1; i >= 0; i-- {
				out = append(out, a.packs[i])
			}
			write(http.StatusOK, map[string]any{"packs": out})
			return
		}
		a.posts++
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, p := range a.packs {
			if p["status"] == "queued" || p["status"] == "building" {
				write(http.StatusConflict, map[string]any{"message": "A pack is already queued or being built for this workspace", "pack": p})
				return
			}
		}
		start, end := body["period_start"], body["period_end"]
		if start == "" {
			start, end = "2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z"
		} else {
			// GovAPI returns the period normalised to UTC.
			s, _ := time.Parse(time.RFC3339, start)
			e, _ := time.Parse(time.RFC3339, end)
			start, end = s.UTC().Format(time.RFC3339), e.UTC().Format(time.RFC3339)
		}
		pack := map[string]any{"pack_id": fmt.Sprintf("pack_%d", len(a.packs)+1), "period_start": start, "period_end": end,
			"status": "queued", "created_at": "2026-10-29T12:00:00Z", "parts": []any{}}
		a.packs = append(a.packs, pack)
		write(http.StatusAccepted, pack)
	})
}

func newEvidencePackResource(t *testing.T, api *evidencePackAPI) *evidencePackResource {
	t.Helper()
	server := httptest.NewServer(api.handler())
	t.Cleanup(server.Close)
	c, err := client.New(client.Config{BaseURL: server.URL, TenantID: "tenant-a", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	previous := evidencePackPollInterval
	evidencePackPollInterval = time.Millisecond
	t.Cleanup(func() { evidencePackPollInterval = previous })
	return &evidencePackResource{client: c}
}

func packPlan(start, end string) evidencePackModel {
	plan := evidencePackModel{PeriodStart: types.StringUnknown(), PeriodEnd: types.StringUnknown()}
	if start != "" {
		plan.PeriodStart, plan.PeriodEnd = types.StringValue(start), types.StringValue(end)
	}
	return plan
}

func TestEvidencePackQueuesThePreviousMonthAndWaitsUntilReady(t *testing.T) {
	api := &evidencePackAPI{listsLeft: 2, finishAs: "ready"}
	r := newEvidencePackResource(t, api)
	ctx := context.Background()

	state, err := r.queue(ctx, packPlan("", ""))
	if err != nil {
		t.Fatal(err)
	}
	if state.ID.ValueString() != "pack_1" || state.Status.ValueString() != "queued" || state.PeriodStart.ValueString() != "2026-09-01T00:00:00Z" {
		t.Fatalf("queued state %+v", state)
	}
	state, err = r.wait(ctx, state, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status.ValueString() != "ready" || state.PartCount.ValueInt64() != 1 || !strings.Contains(state.TotalsJSON.ValueString(), `"attestations":3`) {
		t.Fatalf("ready state %+v", state)
	}
}

func TestEvidencePackKeepsTheConfiguredPeriodAsWritten(t *testing.T) {
	r := newEvidencePackResource(t, &evidencePackAPI{})
	state, err := r.queue(context.Background(), packPlan("2026-10-01T02:00:00+02:00", "2026-10-08T02:00:00+02:00"))
	if err != nil {
		t.Fatal(err)
	}
	// A different spelling in state than in config would be an inconsistent result.
	if state.PeriodStart.ValueString() != "2026-10-01T02:00:00+02:00" {
		t.Fatalf("period_start %q", state.PeriodStart.ValueString())
	}
}

func TestEvidencePackAdoptsTheSamePackInProgress(t *testing.T) {
	api := &evidencePackAPI{}
	r := newEvidencePackResource(t, api)
	ctx := context.Background()
	first, err := r.queue(ctx, packPlan("2026-10-01T00:00:00Z", "2026-10-08T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := r.queue(ctx, packPlan("2026-10-01T02:00:00+02:00", "2026-10-08T02:00:00+02:00"))
	if err != nil {
		t.Fatalf("the same period in another offset should adopt the pack: %v", err)
	}
	if again.ID != first.ID || len(api.packs) != 1 {
		t.Fatalf("adopted %s, packs %d", again.ID.ValueString(), len(api.packs))
	}

	_, err = r.queue(ctx, packPlan("2026-09-01T00:00:00Z", "2026-09-08T00:00:00Z"))
	if err == nil || !strings.Contains(err.Error(), "already building pack pack_1") {
		t.Fatalf("another period while one builds: %v", err)
	}
}

func TestEvidencePackReportsAFailedBuild(t *testing.T) {
	api := &evidencePackAPI{listsLeft: 1, finishAs: "failed"}
	r := newEvidencePackResource(t, api)
	ctx := context.Background()
	state, err := r.queue(ctx, packPlan("", ""))
	if err != nil {
		t.Fatal(err)
	}
	state, err = r.wait(ctx, state, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "signing key unavailable") || state.Status.ValueString() != "failed" {
		t.Fatalf("failed build: %v, state %+v", err, state)
	}
}

func TestEvidencePackWaitTimesOutWithoutLosingThePack(t *testing.T) {
	r := newEvidencePackResource(t, &evidencePackAPI{})
	ctx := context.Background()
	state, err := r.queue(ctx, packPlan("", ""))
	if err != nil {
		t.Fatal(err)
	}
	state, err = r.wait(ctx, state, 0)
	if err == nil || !strings.Contains(err.Error(), "still queued") || state.ID.ValueString() != "pack_1" {
		t.Fatalf("timeout: %v, state %+v", err, state)
	}
}

func TestEvidencePackRefreshForgetsAnUnlistedPack(t *testing.T) {
	r := newEvidencePackResource(t, &evidencePackAPI{})
	_, found, err := r.refresh(context.Background(), evidencePackModel{ID: types.StringValue("pack_gone")})
	if err != nil || found {
		t.Fatalf("found %v, err %v", found, err)
	}
}
