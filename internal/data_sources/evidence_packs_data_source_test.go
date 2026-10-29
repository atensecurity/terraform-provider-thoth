package data_sources

import "testing"

func TestEvidencePackRowsDropPartLocationsAndFilterByStatus(t *testing.T) {
	result := map[string]any{"packs": []any{
		map[string]any{"pack_id": "pack_2", "status": "queued", "parts": []any{}},
		map[string]any{"pack_id": "pack_1", "status": "ready", "totals": map[string]any{"attestations": 3},
			"parts": []any{map[string]any{"part": 1, "key": "packs/pack_1/1.zip"}}},
	}}

	all := evidencePackRows(result, "")
	if len(all) != 2 {
		t.Fatalf("rows %v", all)
	}
	ready := evidencePackRows(result, "ready")
	if len(ready) != 1 {
		t.Fatalf("ready rows %v", ready)
	}
	row := ready[0].(map[string]any)
	if row["pack_id"] != "pack_1" || row["part_count"] != 1 || row["totals"] == nil {
		t.Fatalf("row %v", row)
	}
	if _, ok := row["parts"]; ok {
		t.Fatal("part locations stay with thothctl and the API")
	}
}
