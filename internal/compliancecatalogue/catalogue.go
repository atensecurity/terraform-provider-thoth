// Package compliancecatalogue consumes the generated shared Python vocabulary.
// Classifications are author mappings, never regulatory conformance claims.
package compliancecatalogue

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

//go:embed catalogue.json
var manifestJSON []byte

type Counts struct {
	Enforced      int `json:"enforced" bson:"enforced"`
	EvidenceGap   int `json:"evidence_gap" bson:"evidence_gap"`
	NotActionTime int `json:"not_action_time" bson:"not_action_time"`
	Total         int `json:"total" bson:"total"`
}
type Regime struct {
	Slug              string   `json:"slug" bson:"slug"`
	Canonical         string   `json:"canonical" bson:"canonical"`
	NormalizedAliases []string `json:"normalized_aliases" bson:"normalized_aliases"`
	Counts            Counts   `json:"counts" bson:"counts"`
}
type Control struct {
	ID             string `json:"id" bson:"id"`
	Name           string `json:"name" bson:"name"`
	Regulation     string `json:"regulation" bson:"regulation"`
	Classification string `json:"classification" bson:"classification"`
}
type Contract struct {
	SchemaVersion   int       `json:"schema_version" bson:"schema_version"`
	CatalogueSHA256 string    `json:"catalogue_sha256" bson:"catalogue_sha256"`
	EvaluatorSHA256 string    `json:"evaluator_sha256" bson:"evaluator_sha256"`
	Regimes         []Regime  `json:"regimes" bson:"regimes"`
	Controls        []Control `json:"controls" bson:"controls"`
}

// Manifest returns a caller-owned copy of the embedded release contract.
func Manifest() Contract {
	var value Contract
	if err := json.Unmarshal(manifestJSON, &value); err != nil {
		panic(fmt.Sprintf("invalid embedded compliance contract: %v", err))
	}
	return value
}

func NormalizeAlias(value string) string {
	return strings.Map(func(r rune) rune {
		// Python's unicode \s additionally recognizes these ASCII separators.
		if unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) || r == '_' || r == '-' || r == '/' {
			return -1
		}
		return unicode.ToLower(r)
	}, value)
}
func Canonicalize(value string) (string, error) {
	normalized := NormalizeAlias(value)
	accepted := []string{}
	for _, regime := range Manifest().Regimes {
		accepted = append(accepted, regime.Slug)
		for _, alias := range regime.NormalizedAliases {
			if normalized == alias {
				return regime.Canonical, nil
			}
		}
	}
	return "", fmt.Errorf("unknown regulatory regime %q; accepted values: %s", value, strings.Join(accepted, ", "))
}
func CanonicalizeSet(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		canonical, err := Canonicalize(value)
		if err != nil {
			return nil, err
		}
		if seen[canonical] {
			return nil, fmt.Errorf("declared regulatory regimes must be distinct: %s", canonical)
		}
		seen[canonical] = true
		result = append(result, canonical)
	}
	sort.Strings(result)
	return result, nil
}
func Coverage(values []string) (map[string]Counts, []string) {
	catalogue := map[string]Counts{}
	for _, regime := range Manifest().Regimes {
		catalogue[regime.Canonical] = regime.Counts
	}
	counts := map[string]Counts{}
	gaps := []string{}
	for _, value := range values {
		counts[value] = catalogue[value]
		if counts[value].Enforced == 0 {
			gaps = append(gaps, value)
		}
	}
	sort.Strings(gaps)
	return counts, gaps
}
