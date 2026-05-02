package main

import (
	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"

	"github.com/atensecurity/terraform-provider-thoth/internal/provider"
)

// providerFactory keeps provider construction centralized in provider.go.
func providerFactory(version string) func() frameworkprovider.Provider {
	return provider.New(version)
}
