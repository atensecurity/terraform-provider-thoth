package data_sources

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ datasource.DataSource = &mcpVendorDataSource{}

type mcpVendorDataSource struct {
	client *client.Client
}

type mcpVendorDataSourceModel struct {
	VendorID     types.String `tfsdk:"vendor_id"`
	ResponseJSON types.String `tfsdk:"response_json"`
}

func NewMCPVendorDataSource() datasource.DataSource {
	return &mcpVendorDataSource{}
}

func (d *mcpVendorDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mcp_vendor"
}

func (d *mcpVendorDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads one MCP vendor entry from the tenant vendor registry.",
		Attributes: map[string]schema.Attribute{
			"vendor_id": schema.StringAttribute{
				Required:    true,
				Description: "Stable MCP vendor identifier.",
			},
			"response_json": schema.StringAttribute{
				Computed:    true,
				Description: "Vendor record as JSON.",
			},
		},
	}
}

func (d *mcpVendorDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	data := tfhelpers.RequireDataSourceClient(req, resp)
	if data == nil {
		return
	}
	d.client = data.Client
}

func (d *mcpVendorDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state mcpVendorDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vendorID := strings.TrimSpace(state.VendorID.ValueString())
	if vendorID == "" {
		resp.Diagnostics.AddError("Missing vendor_id", "vendor_id must be set.")
		return
	}

	row, err := d.client.GetMCPVendor(ctx, vendorID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading MCP vendor", err.Error())
		return
	}

	resolvedVendorID := strings.TrimSpace(tfhelpers.GetString(row, "vendor_id"))
	if resolvedVendorID == "" {
		resolvedVendorID = vendorID
	}
	state.VendorID = types.StringValue(resolvedVendorID)
	state.ResponseJSON = types.StringValue(tfhelpers.ToJSONString(row))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
