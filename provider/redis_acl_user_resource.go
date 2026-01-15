package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &RedisAclUserResource{}

func NewRedisAclUserResource() resource.Resource {
	return &RedisAclUserResource{}
}

type RedisAclUserResource struct {
	providerData *RedisProviderModel
}

func (e *RedisAclUserResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	e.providerData = req.ProviderData.(*RedisProviderModel)
}

func (e *RedisAclUserResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acl_user"
}

type RedisAclUserResourceModel struct {
	Name              types.String `tfsdk:"name"`
	enabled           types.Bool   `tfsdk:"enabled"`
	PasswordWo        types.Int64  `tfsdk:"password_wo"`
	PasswordWoVersion types.String `tfsdk:"password_wo_version"`
	AclCategories     types.String `tfsdk:"acl_categories"`
	Commands          types.Int64  `tfsdk:"commands"`
	Keys              types.Int64  `tfsdk:"keys"`
	Channels          types.Int64  `tfsdk:"channels"`
	FullAccess        types.Bool   `tfsdk:"full_access"`
}

func (e *RedisAclUserResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name":                schema.StringAttribute{Required: true},
			"enabled":             schema.BoolAttribute{Optional: true},
			"password_wo":         schema.StringAttribute{Required: true, Sensitive: true},
			"password_wo_version": schema.StringAttribute{Required: true},
			"acl_categories":      schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"commands":            schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"keys":                schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"channels":            schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"full_access":         schema.BoolAttribute{Optional: true},
		},
	}
}

func (e *RedisAclUserResource) Create(context.Context, resource.CreateRequest, *resource.CreateResponse) {
	panic("unimplemented")
}

func (e *RedisAclUserResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
	panic("unimplemented")
}

func (e *RedisAclUserResource) Read(context.Context, resource.ReadRequest, *resource.ReadResponse) {
	panic("unimplemented")
}

func (e *RedisAclUserResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	panic("unimplemented")
}
