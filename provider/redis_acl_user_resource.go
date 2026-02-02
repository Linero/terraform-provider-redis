package provider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/redis/go-redis/v9"
)

var _ resource.Resource = &RedisAclUserResource{}

func NewRedisAclUserResource() resource.Resource {
	return &RedisAclUserResource{}
}

type RedisAclUserResource struct {
	providerData *RedisProviderModel
}

type RedisAclUserResourceModel struct {
	Name              types.String `tfsdk:"name"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	PasswordWo        types.String `tfsdk:"password_wo"`
	PasswordWoVersion types.String `tfsdk:"password_wo_version"`
	Commands          types.List   `tfsdk:"commands"`
	ExcludedCommands  types.List   `tfsdk:"excluded_commands"`
	Categories        types.List   `tfsdk:"categories"`
	Keys              types.List   `tfsdk:"keys"`
	ReadonlyKeys      types.List   `tfsdk:"readonly_keys"`
	WriteonlyKeys     types.List   `tfsdk:"writeonly_keys"`
	Channels          types.List   `tfsdk:"channels"`
	AclSave           types.Bool   `tfsdk:"acl_save"`
}

func (r *RedisAclUserResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.providerData = req.ProviderData.(*RedisProviderModel)
}

func (r *RedisAclUserResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acl_user"
}

func (r *RedisAclUserResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the ACL user.",
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether the ACL user is enabled.",
				Default:     booldefault.StaticBool(true),
				Computed:    true,
			},
			"password_wo": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Description: "Write-only password for the ACL user. Password is hashed with SHA256 before being stored in Redis.",
			},
			"password_wo_version": schema.StringAttribute{
				Required:    true,
				Description: "Version string for password. Changing this value forces a password update even if password_wo hasn't changed in the configuration. Use this to rotate passwords.",
			},
			"commands": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "ACL commands for the user (e.g., 'config|get', 'keys', 'all').",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"excluded_commands": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "ACL commands to exclude for the user (e.g., 'config|get', 'keys', 'all').",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"categories": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "ACL categories for the user (e.g., 'read', 'write', 'admin').",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"keys": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key patterns the user can access (without ~ prefix).",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"readonly_keys": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key patterns the user can only read (without %R~ prefix).",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"writeonly_keys": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key patterns the user can only write (without %W~ prefix).",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"channels": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Pub/Sub channel patterns the user can access (without & prefix).",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"acl_save": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to save the ACL user configuration.",
				Default:     booldefault.StaticBool(true),
				Computed:    true,
			},
		},
	}
}

func (r *RedisAclUserResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

func (r *RedisAclUserResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, config RedisAclUserResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := r.AclGetUser(plan.Name.ValueString(), ctx); err == nil {
		resp.Diagnostics.AddError("User already exists", fmt.Sprintf("ACL user '%s' already exists, consider importing it", plan.Name.ValueString()))
		return
	}

	if config.PasswordWo.IsNull() && config.PasswordWo.IsUnknown() {
		resp.Diagnostics.AddError("Failed to create ACL user", "password_wo is null or empty")
		return
	}

	passwordHash := hashPassword(config.PasswordWo.ValueString())

	_, err := r.AclSetUser(&plan, ctx, []string{passwordHash})

	if err != nil {
		resp.Diagnostics.AddError("Failed to create ACL user", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *RedisAclUserResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state RedisAclUserResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	aclData, err := r.AclGetUser(state.Name.ValueString(), ctx)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to read ACL user", err.Error())
		return
	}

	aclMap := parseAclDataToMap(aclData)

	if err := loadAclMapIntoState(ctx, aclMap, &state, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Failed to load ACL user data", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *RedisAclUserResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state, config RedisAclUserResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	aclData, err := r.AclGetUser(state.Name.ValueString(), ctx)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to read ACL user", err.Error())
		return
	}

	aclMap := parseAclDataToMap(aclData)

	passwordHashes := parsePasswordHashesFromAclMap(aclMap)

	if plan.PasswordWoVersion.ValueString() != state.PasswordWoVersion.ValueString() {
		if !config.PasswordWo.IsNull() && !config.PasswordWo.IsUnknown() {
			passwordHash := hashPassword(config.PasswordWo.ValueString())
			passwordHashes = []string{passwordHash}
		}
	}

	if _, err := r.AclSetUser(&plan, ctx, passwordHashes); err != nil {
		resp.Diagnostics.AddError("Failed to update ACL user", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *RedisAclUserResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state RedisAclUserResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.AclDelUser(state.Name.ValueString(), ctx, state.AclSave.ValueBool())
	if err != nil {
		resp.Diagnostics.AddError("Failed to delete ACL user", err.Error())
		return
	}
}

func (r *RedisAclUserResource) AclGetUser(username string, ctx context.Context) (map[any]any, error) {
	client := r.redisClient()
	res, err := client.Do(ctx, "ACL", "GETUSER", username).Result()
	if err != nil {
		return nil, err
	}

	aclData, ok := res.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("unexpected response format from Redis")
	}
	return aclData, nil
}

func (r *RedisAclUserResource) AclSetUser(model *RedisAclUserResourceModel, ctx context.Context, hashedPasswords []string) (bool, error) {
	client := r.redisClient()
	rules := buildACLRules(model, hashedPasswords)
	username := model.Name.ValueString()
	args := append([]any{"ACL", "SETUSER", username}, toAny(rules)...)

	if err := client.Do(ctx, args...).Err(); err != nil {
		return false, err
	}
	if model.AclSave.ValueBool() {
		if _, err := r.AclSave(ctx); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (r *RedisAclUserResource) AclDelUser(username string, ctx context.Context, saveChanges bool) (bool, error) {
	client := r.redisClient()
	if err := client.Do(ctx, "ACL", "DELUSER", username).Err(); err != nil {
		return false, err
	}
	if saveChanges {
		if _, err := r.AclSave(ctx); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (r *RedisAclUserResource) AclSave(ctx context.Context) (bool, error) {
	client := r.redisClient()

	if err := client.Do(ctx, "ACL", "SAVE").Err(); err != nil {
		return false, err
	}
	return true, nil
}

func parseAclDataToMap(aclData map[any]any) map[string]any {
	aclMap := make(map[string]any)
	for k, v := range aclData {
		aclMap[k.(string)] = v
	}
	return aclMap
}

func loadAclMapIntoState(ctx context.Context, aclMap map[string]any, state *RedisAclUserResourceModel, diags *diag.Diagnostics) error {

	enabled := parseEnabledFromFlags(aclMap)
	state.Enabled = types.BoolValue(enabled)

	categories, commands, excludedCommands := parseCommandsFromAclMap(aclMap)
	if commandsList, err := convertToTypesList(ctx, commands, diags); err == nil {
		state.Commands = commandsList
	}

	if excludedCommandsList, err := convertToTypesList(ctx, excludedCommands, diags); err == nil {
		state.ExcludedCommands = excludedCommandsList
	}

	if categoriesList, err := convertToTypesList(ctx, categories, diags); err == nil {
		state.Categories = categoriesList
	}

	keys, readonlyKeys, writeonlyKeys := parseKeysFromAclMap(aclMap)
	if keyList, err := convertToTypesList(ctx, keys, diags); err == nil {
		state.Keys = keyList
	}
	if readonlyList, err := convertToTypesList(ctx, readonlyKeys, diags); err == nil {
		state.ReadonlyKeys = readonlyList
	}
	if writeonlyList, err := convertToTypesList(ctx, writeonlyKeys, diags); err == nil {
		state.WriteonlyKeys = writeonlyList
	}

	channels := parseChannelsFromAclMap(aclMap)
	if channelList, err := convertToTypesList(ctx, channels, diags); err == nil {
		state.Channels = channelList
	}

	return nil
}

func parsePasswordHashesFromAclMap(aclMap map[string]any) []string {
	passwordsData, ok := aclMap["passwords"].([]any)
	if !ok {
		return []string{}
	}
	passwords := []string{}
	for _, password := range passwordsData {
		if passwordStr, ok := password.(string); ok {
			passwords = append(passwords, passwordStr)
		}
	}
	return passwords
}

func parseEnabledFromFlags(aclMap map[string]any) bool {
	flags, ok := aclMap["flags"].([]any)
	if !ok {
		return false
	}

	for _, flag := range flags {
		if flagStr, ok := flag.(string); ok && flagStr == "on" {
			return true
		}
	}
	return false
}

func parseCommandsFromAclMap(aclMap map[string]any) (
	categories []string,
	commands []string,
	excludedCommands []string,
) {
	commandsData, ok := aclMap["commands"].(string)
	if !ok || commandsData == "" {
		return
	}

	tokens := strings.Split(commandsData, " ")

	for _, token := range tokens {
		switch {
		case strings.HasPrefix(token, "-@"):
			continue
		case strings.HasPrefix(token, "+@"):
			categories = append(categories, strings.TrimPrefix(token, "+@"))

		case strings.HasPrefix(token, "-"):
			excludedCommands = append(excludedCommands, strings.TrimPrefix(token, "-"))

		case strings.HasPrefix(token, "+"):
			commands = append(commands, strings.TrimPrefix(token, "+"))
		}
	}

	return
}

func parseKeysFromAclMap(aclMap map[string]any) (keys, readonlyKeys, writeonlyKeys []string) {
	keysDataStr, ok := aclMap["keys"].(string)
	keysData := strings.Split(keysDataStr, " ")
	if !ok {
		return []string{}, []string{}, []string{}
	}

	keys = []string{}
	readonlyKeys = []string{}
	writeonlyKeys = []string{}

	for _, keyStr := range keysData {
		if after, ok0 := strings.CutPrefix(keyStr, "%R~"); ok0 {
			readonlyKeys = append(readonlyKeys, after)
		} else if after0, ok1 := strings.CutPrefix(keyStr, "%W~"); ok1 {
			writeonlyKeys = append(writeonlyKeys, after0)
		} else if after1, ok2 := strings.CutPrefix(keyStr, "~"); ok2 {
			keys = append(keys, after1)
		}

	}

	return keys, readonlyKeys, writeonlyKeys
}

func parseChannelsFromAclMap(aclMap map[string]any) []string {
	channelsData, ok := aclMap["channels"].(string)
	channels := strings.Split(channelsData, " ")
	if !ok {
		return []string{}
	}

	var channelStrs []string
	for _, channelStr := range channels {
		if after, ok0 := strings.CutPrefix(channelStr, "&"); ok0 {
			channelStrs = append(channelStrs, after)
		}
	}

	return channelStrs
}

func convertToTypesList(ctx context.Context, items []string, diags *diag.Diagnostics) (types.List, error) {
	if len(items) > 0 {
		list, listDiags := types.ListValueFrom(ctx, types.StringType, items)
		diags.Append(listDiags...)
		if listDiags.HasError() {
			return types.ListNull(types.StringType), fmt.Errorf("failed to convert list")
		}
		return list, nil
	}
	emptyList, listDiags := types.ListValueFrom(ctx, types.StringType, []string{})
	diags.Append(listDiags...)
	return emptyList, nil
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	hashString := fmt.Sprintf("%x", hash)
	return hashString
}

func buildACLRules(m *RedisAclUserResourceModel, hashedPasswords []string) []string {
	rules := []string{}

	rules = append(rules, "reset")

	if m.Enabled.ValueBool() {
		rules = append(rules, "on")
	} else {
		rules = append(rules, "off")
	}

	for _, hashedPassword := range hashedPasswords {
		rules = append(rules, "#"+hashedPassword)
	}

	appendList := func(prefix string, list []types.String) {
		for _, v := range list {
			rules = append(rules, prefix+v.ValueString())
		}
	}
	appendList("~", toStringList(m.Keys))
	appendList("%R~", toStringList(m.ReadonlyKeys))
	appendList("%W~", toStringList(m.WriteonlyKeys))
	appendList("&", toStringList(m.Channels))

	categories := toStringList(m.Categories)
	if stringInList("all", categories) {
		rules = append(rules, "+@all")
	} else {
		appendList("+@", categories)
		appendList("+", toStringList(m.Commands))
		appendList("-", toStringList(m.ExcludedCommands))
	}

	return rules
}

func toStringList(val types.List) []types.String {
	if val.IsNull() || val.IsUnknown() {
		return nil
	}
	var out []types.String
	_ = val.ElementsAs(context.Background(), &out, false)
	return out
}

func (e *RedisAclUserResource) redisClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     e.providerData.Address.ValueString(),
		Username: e.providerData.Username.ValueString(),
		Password: e.providerData.Password.ValueString(),
	})
}

func toAny[T any](in []T) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func stringInList(target string, list []types.String) bool {
	for _, s := range list {
		if s.ValueString() == target {
			return true
		}
	}
	return false
}
