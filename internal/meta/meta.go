package meta

import "github.com/atensecurity/terraform-provider-thoth/internal/client"

// ClientData is shared provider state passed to resources and data sources.
type ClientData struct {
	Client   *client.Client
	TenantID string
}
