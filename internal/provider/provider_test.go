package provider

import "testing"

func TestDefaultAPIBaseURL(t *testing.T) {
	cases := []struct {
		tenant, apex, want string
	}{
		{"5d3e1e69cdc14fb4911e4cf7d2cfde25", "", "https://api.atensecurity.com"},
		// The shared runtime has one address whatever the apex domain.
		{"5d3e1e69cdc14fb4911e4cf7d2cfde25", "example.com", "https://api.atensecurity.com"},
		{"acme", "", "https://grid.acme.atensecurity.com"},
		{"acme", "example.com", "https://grid.acme.example.com"},
		// Not a workspace ID: uppercase, or the wrong length.
		{"5D3E1E69CDC14FB4911E4CF7D2CFDE25", "", "https://grid.5D3E1E69CDC14FB4911E4CF7D2CFDE25.atensecurity.com"},
		{"5d3e1e69cdc14fb4911e4cf7d2cfde2", "", "https://grid.5d3e1e69cdc14fb4911e4cf7d2cfde2.atensecurity.com"},
	}
	for _, tc := range cases {
		if got := defaultAPIBaseURL(tc.tenant, tc.apex); got != tc.want {
			t.Errorf("defaultAPIBaseURL(%q, %q) = %q, want %q", tc.tenant, tc.apex, got, tc.want)
		}
	}
}
