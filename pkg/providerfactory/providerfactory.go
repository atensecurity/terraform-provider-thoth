package providerfactory

import (
	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"

	internalprovider "github.com/atensecurity/terraform-provider-thoth/internal/provider"
)

// New returns the Terraform Plugin Framework provider factory for thoth.
func New(version string) func() frameworkprovider.Provider {
	return internalprovider.New(version)
}
