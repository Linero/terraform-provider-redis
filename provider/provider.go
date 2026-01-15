package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = (*RedisProvider)(nil)
var _ provider.ProviderWithEphemeralResources = (*RedisProvider)(nil)

type RedisProvider struct{}

func New() func() provider.Provider {
	return func() provider.Provider {
		return &RedisProvider{}
	}
}

type RedisProviderModel struct {
	Address  types.String `tfsdk:"address"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
}

func (p *RedisProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				Required: true,
			},
			"Username": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
			},
			"Password": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
			},
		},
	}
}
func (p *RedisProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data RedisProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	providerData := &RedisProviderModel{
		Address:  data.Address,
		Username: data.Username,
		Password: data.Password,
	}

	resp.ResourceData = providerData
	resp.DataSourceData = providerData
	resp.EphemeralResourceData = providerData
}

func (p *RedisProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "redis"
}

func (p *RedisProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *RedisProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewRedisAclUserResource,
	}
}

func (p *RedisProvider) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{}
}
