package resources

import (
	"reflect"
	"strings"
	"testing"
)

// Rows mirror backend/go/cmd/govapi/api_key_gateway_scope_test.go so the
// client-side rules cannot drift from the server's.
func TestNormalizeGatewayKeyScopeTable(t *testing.T) {
	long := strings.Repeat("a", gatewayKeyScopeMaxEntryLen+1)
	many := make([]string, gatewayKeyScopeMaxEntries+1)
	for i := range many {
		many[i] = "agent-" + strings.Repeat("x", i/26) + string(rune('a'+i%26))
	}
	okTools := []string{"metabase__run_query"}
	okAgents := []string{"agent-a"}
	cases := map[string]struct {
		kind          string
		agents, tools []string
		wantErr       bool
	}{
		"missing agents":      {gatewayKeyKind, nil, okTools, true},
		"missing tools":       {gatewayKeyKind, okAgents, nil, true},
		"empty lists":         {gatewayKeyKind, []string{}, []string{}, true},
		"bare star tool":      {gatewayKeyKind, okAgents, []string{"*"}, true},
		"bare star agent":     {gatewayKeyKind, []string{"*"}, okTools, true},
		"mixed star":          {gatewayKeyKind, okAgents, []string{"meta*base__x*"}, true},
		"double star":         {gatewayKeyKind, okAgents, []string{"**"}, true},
		"short prefix":        {gatewayKeyKind, okAgents, []string{"me*"}, true},
		"empty entry":         {gatewayKeyKind, okAgents, []string{""}, true},
		"whitespace entry":    {gatewayKeyKind, okAgents, []string{"metabase__run query"}, true},
		"padded entry":        {gatewayKeyKind, okAgents, []string{" metabase__run_query"}, true},
		"too long":            {gatewayKeyKind, okAgents, []string{"metabase__" + long}, true},
		"too many":            {gatewayKeyKind, many, okTools, true},
		"tool lacks upstream": {gatewayKeyKind, okAgents, []string{"run_query"}, true},
		"prefix agent":        {gatewayKeyKind, []string{"agent-*"}, okTools, true},
		"lists on plain key":  {"", okAgents, okTools, true},
		"agents on plain key": {"", okAgents, nil, true},
		"star inside":         {gatewayKeyKind, okAgents, []string{"up__a*b"}, true},
		"star leads":          {gatewayKeyKind, okAgents, []string{"*__tool"}, true},
		"star after prefix":   {gatewayKeyKind, okAgents, []string{"up__*x"}, true},
		"double star suffix":  {gatewayKeyKind, okAgents, []string{"up__**"}, true},
		"star in upstream":    {gatewayKeyKind, okAgents, []string{"up*__tool"}, true},
		"star in agent":       {gatewayKeyKind, []string{"agent*a"}, okTools, true},
		"cyrillic lookalike":  {gatewayKeyKind, okAgents, []string{"metab\u0430se__run"}, true},
		"zero width space":    {gatewayKeyKind, okAgents, []string{"metabase__ru\u200bn"}, true},
		"dotless/dotted I":    {gatewayKeyKind, okAgents, []string{"\u0130nfo__run"}, true},
		"no upstream":         {gatewayKeyKind, okAgents, []string{"__x"}, true},
		"non ascii prefix":    {gatewayKeyKind, okAgents, []string{"\u00e9__*"}, true},
		"multibyte prefix":    {gatewayKeyKind, okAgents, []string{"\u00e9\u00e9__*"}, true},
		"upstream with __":    {gatewayKeyKind, okAgents, []string{"a__b__c"}, false},
		"empty tool":          {gatewayKeyKind, okAgents, []string{"metabase__"}, true},
		"bad tool char":       {gatewayKeyKind, okAgents, []string{"metabase__run/x"}, true},
		"cyrillic agent":      {gatewayKeyKind, []string{"agent-\u0430"}, okTools, true},
		"zero width agent":    {gatewayKeyKind, []string{"agent\u200b-a"}, okTools, true},
		"dotted I agent":      {gatewayKeyKind, []string{"agent-\u0130"}, okTools, true},
		"valid dotted tool":   {gatewayKeyKind, okAgents, []string{"metabase__db.run:v-2"}, false},
		"ambiguous a___b":     {gatewayKeyKind, okAgents, []string{"a___b"}, true},
		"upstream ends _":     {gatewayKeyKind, okAgents, []string{"a___*"}, true},
		"tool starts _":       {gatewayKeyKind, okAgents, []string{"a___b*"}, true},
		"trailing _ upstream": {gatewayKeyKind, okAgents, []string{"a___"}, true},
		"empty upstream *":    {gatewayKeyKind, okAgents, []string{"__*"}, true},
		"dot in upstream":     {gatewayKeyKind, okAgents, []string{"u.p__x"}, true},
		"star mid prefix":     {gatewayKeyKind, okAgents, []string{"up__s*x"}, true},
		"star mid twice":      {gatewayKeyKind, okAgents, []string{"up__s*x*"}, true},
		"u star p":            {gatewayKeyKind, okAgents, []string{"u*p__x"}, true},
		"star under minimum":  {gatewayKeyKind, okAgents, []string{"u_*"}, true},
		"trailing newline":    {gatewayKeyKind, okAgents, []string{"up__*\n"}, true},
		"tab in tool":         {gatewayKeyKind, okAgents, []string{"up__sea\trch"}, true},
		"nul in tool":         {gatewayKeyKind, okAgents, []string{"up__sea\x00rch"}, true},
		"del in tool":         {gatewayKeyKind, okAgents, []string{"up__sea\x7frch"}, true},
		"sharp s":             {gatewayKeyKind, okAgents, []string{"up__stra\u00dfe"}, true},
		"fullwidth s":         {gatewayKeyKind, okAgents, []string{"up__\uff53earch"}, true},
		"cyrillic u":          {gatewayKeyKind, okAgents, []string{"\u0443p__search"}, true},
		"zero width tool":     {gatewayKeyKind, okAgents, []string{"up__s\u200bearch"}, true},
		"multibyte star":      {gatewayKeyKind, okAgents, []string{"\u00e9\u00e9*__x"}, true},
		"slash in tool":       {gatewayKeyKind, okAgents, []string{"up__a/b"}, true},
		"slash in agent":      {gatewayKeyKind, []string{"a/b"}, okTools, true},
		"backslash agent":     {gatewayKeyKind, []string{"a\\b"}, okTools, true},
		"zero width agent2":   {gatewayKeyKind, []string{"agent\u200b"}, okTools, true},
		"cyrillic agent2":     {gatewayKeyKind, []string{"\u0430gent"}, okTools, true},
		"star agent":          {gatewayKeyKind, []string{"gw-a*t"}, okTools, true},
		"fullwidth agent":     {gatewayKeyKind, []string{"\uff47w-agent"}, okTools, true},
		"too long tool":       {gatewayKeyKind, okAgents, []string{"up__" + strings.Repeat("a", 260)}, true},
		"padded trailing":     {gatewayKeyKind, okAgents, []string{"up__search "}, true},
		"agent 129 chars":     {gatewayKeyKind, []string{strings.Repeat("a", 129)}, okTools, true},
		"agent 128 chars":     {gatewayKeyKind, []string{strings.Repeat("a", 128)}, okTools, false},
		"tool part 129 chars": {gatewayKeyKind, okAgents, []string{"up__" + strings.Repeat("a", 129)}, true},
		"tool part 128 chars": {gatewayKeyKind, okAgents, []string{"up__" + strings.Repeat("a", 128)}, false},
		"upstream 129 chars":  {gatewayKeyKind, okAgents, []string{strings.Repeat("u", 129) + "__x"}, true},
		"both parts 128":      {gatewayKeyKind, okAgents, []string{strings.Repeat("u", 128) + "__" + strings.Repeat("a", 128)}, false},
		"valid":               {gatewayKeyKind, okAgents, okTools, false},
		"valid prefix tool":   {gatewayKeyKind, okAgents, []string{"metabase__*"}, false},
		"plain key no lists":  {"", nil, nil, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := normalizeGatewayKeyScope(tc.kind, tc.agents, tc.tools)
			if tc.wantErr != (err != nil) {
				t.Fatalf("wantErr=%v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestNormalizeGatewayKeyScopeLowersDedupesAndSorts(t *testing.T) {
	agents, tools, err := normalizeGatewayKeyScope(gatewayKeyKind,
		[]string{"Agent-B", "agent-a", "AGENT-A"}, []string{"Metabase__Run", "github__*", "metabase__run"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(agents, []string{"agent-a", "agent-b"}) || !reflect.DeepEqual(tools, []string{"github__*", "metabase__run"}) {
		t.Fatalf("got %v %v", agents, tools)
	}
}

func TestValidateGatewayKeyKind(t *testing.T) {
	cases := map[string]struct {
		kind, scope string
		perms       []string
		wantErr     bool
	}{
		"plain key":         {"", "endpoint", []string{"read", "execute"}, false},
		"plain fleet":       {"", "fleet", []string{"read"}, false},
		"gateway":           {"mcp_gateway", "endpoint", []string{"execute"}, false},
		"gateway fleet":     {"mcp_gateway", "fleet", []string{"execute"}, true},
		"gateway agent":     {"mcp_gateway", "agent", []string{"execute"}, true},
		"gateway read":      {"mcp_gateway", "endpoint", []string{"read", "execute"}, true},
		"gateway read only": {"mcp_gateway", "endpoint", []string{"read"}, true},
		"gateway no perms":  {"mcp_gateway", "endpoint", nil, true},
		"gateway two exec":  {"mcp_gateway", "endpoint", []string{"execute", "execute"}, true},
		"unknown kind":      {"other", "endpoint", []string{"execute"}, true},
		"upper-case kind":   {"MCP_GATEWAY", "endpoint", []string{"execute"}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateGatewayKeyKind(tc.kind, tc.scope, tc.perms)
			if tc.wantErr != (err != nil) {
				t.Fatalf("wantErr=%v, got %v", tc.wantErr, err)
			}
		})
	}
}
