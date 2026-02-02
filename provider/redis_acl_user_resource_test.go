package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRedisAclUserResource(t *testing.T) {
	t.Run("creates new resource instance", func(t *testing.T) {
		resource := NewRedisAclUserResource()

		assert.NotNil(t, resource)
		assert.IsType(t, &RedisAclUserResource{}, resource)
	})
}

func TestRedisAclUserResource_Metadata(t *testing.T) {
	t.Run("sets correct type name", func(t *testing.T) {
		r := &RedisAclUserResource{}
		req := resource.MetadataRequest{
			ProviderTypeName: "redis",
		}
		resp := &resource.MetadataResponse{}

		r.Metadata(context.Background(), req, resp)

		assert.Equal(t, "redis_acl_user", resp.TypeName)
	})
}

func TestRedisAclUserResource_Configure(t *testing.T) {
	t.Run("handles nil provider data", func(t *testing.T) {
		r := &RedisAclUserResource{}
		req := resource.ConfigureRequest{
			ProviderData: nil,
		}
		resp := &resource.ConfigureResponse{}

		r.Configure(context.Background(), req, resp)

		assert.Nil(t, r.providerData)
		assert.False(t, resp.Diagnostics.HasError())
	})

	t.Run("sets provider data correctly", func(t *testing.T) {
		r := &RedisAclUserResource{}
		providerData := &RedisProviderModel{
			Address:  types.StringValue("localhost:6379"),
			Username: types.StringValue("admin"),
			Password: types.StringValue("secret"),
		}
		req := resource.ConfigureRequest{
			ProviderData: providerData,
		}
		resp := &resource.ConfigureResponse{}

		r.Configure(context.Background(), req, resp)

		require.NotNil(t, r.providerData)
		assert.Equal(t, "localhost:6379", r.providerData.Address.ValueString())
		assert.Equal(t, "admin", r.providerData.Username.ValueString())
		assert.Equal(t, "secret", r.providerData.Password.ValueString())
	})
}

func TestRedisAclUserResource_Schema(t *testing.T) {
	t.Run("has all required attributes", func(t *testing.T) {
		r := &RedisAclUserResource{}
		req := resource.SchemaRequest{}
		resp := &resource.SchemaResponse{}

		r.Schema(context.Background(), req, resp)

		assert.NotNil(t, resp.Schema.Attributes)

		// Check required attributes
		assert.Contains(t, resp.Schema.Attributes, "name")
		assert.Contains(t, resp.Schema.Attributes, "enabled")
		assert.Contains(t, resp.Schema.Attributes, "password_wo")
		assert.Contains(t, resp.Schema.Attributes, "password_wo_version")
		assert.Contains(t, resp.Schema.Attributes, "commands")
		assert.Contains(t, resp.Schema.Attributes, "keys")
		assert.Contains(t, resp.Schema.Attributes, "channels")
	})

	t.Run("password_wo is sensitive", func(t *testing.T) {
		r := &RedisAclUserResource{}
		req := resource.SchemaRequest{}
		resp := &resource.SchemaResponse{}

		r.Schema(context.Background(), req, resp)

		passwordAttr := resp.Schema.Attributes["password_wo"]
		stringAttr, ok := passwordAttr.(schema.StringAttribute)
		require.True(t, ok)
		assert.True(t, stringAttr.Sensitive)
	})
}

func TestBuildACLRules(t *testing.T) {
	t.Run("builds rules with enabled user", func(t *testing.T) {
		model := &RedisAclUserResourceModel{
			Name:    types.StringValue("testuser"),
			Enabled: types.BoolValue(true),
		}

		rules := buildACLRules(model, []string{})

		assert.Contains(t, rules, "on")
		assert.NotContains(t, rules, "off")
	})

	t.Run("builds rules with disabled user", func(t *testing.T) {
		model := &RedisAclUserResourceModel{
			Name:    types.StringValue("testuser"),
			Enabled: types.BoolValue(false),
		}

		rules := buildACLRules(model, []string{})

		assert.Contains(t, rules, "off")
		assert.NotContains(t, rules, "on")
	})

	t.Run("builds rules with password", func(t *testing.T) {
		model := &RedisAclUserResourceModel{
			Name:       types.StringValue("testuser"),
			Enabled:    types.BoolValue(true),
			PasswordWo: types.StringValue("mypassword"),
		}

		passwordHash := hashPassword(model.PasswordWo.ValueString())

		rules := buildACLRules(model, []string{passwordHash})

		assert.Contains(t, rules, "reset")
		assert.Contains(t, rules, "#"+passwordHash)
	})

	t.Run("builds rules with categories", func(t *testing.T) {
		categories, _ := types.ListValueFrom(
			context.Background(),
			types.StringType,
			[]string{"get", "set"},
		)

		model := &RedisAclUserResourceModel{
			Name:       types.StringValue("testuser"),
			Enabled:    types.BoolValue(true),
			Categories: categories,
		}

		rules := buildACLRules(model, []string{})

		assert.Contains(t, rules, "+@get")
		assert.Contains(t, rules, "+@set")
	})

	t.Run("builds rules with keys", func(t *testing.T) {
		keys, _ := types.ListValueFrom(
			context.Background(),
			types.StringType,
			[]string{"app:*", "user:*"},
		)

		model := &RedisAclUserResourceModel{
			Name:    types.StringValue("testuser"),
			Enabled: types.BoolValue(true),
			Keys:    keys,
		}

		rules := buildACLRules(model, []string{})

		assert.Contains(t, rules, "~app:*")
		assert.Contains(t, rules, "~user:*")
	})

	t.Run("builds rules with channels", func(t *testing.T) {
		channels, _ := types.ListValueFrom(
			context.Background(),
			types.StringType,
			[]string{"notifications:*", "alerts:*"},
		)

		model := &RedisAclUserResourceModel{
			Name:     types.StringValue("testuser"),
			Enabled:  types.BoolValue(true),
			Channels: channels,
		}

		rules := buildACLRules(model, []string{})

		assert.Contains(t, rules, "&notifications:*")
		assert.Contains(t, rules, "&alerts:*")
	})

	t.Run("builds comprehensive rules", func(t *testing.T) {
		categories, _ := types.ListValueFrom(
			context.Background(),
			types.StringType,
			[]string{"read", "write"},
		)
		commands, _ := types.ListValueFrom(
			context.Background(),
			types.StringType,
			[]string{"config|get"},
		)
		excludedCommands, _ := types.ListValueFrom(
			context.Background(),
			types.StringType,
			[]string{"config|set"},
		)
		keys, _ := types.ListValueFrom(
			context.Background(),
			types.StringType,
			[]string{"app:*"},
		)
		channels, _ := types.ListValueFrom(
			context.Background(),
			types.StringType,
			[]string{"notifications:*"},
		)

		model := &RedisAclUserResourceModel{
			Name:              types.StringValue("testuser"),
			Enabled:           types.BoolValue(true),
			PasswordWo:        types.StringValue("mypassword"),
			PasswordWoVersion: types.StringValue("v1"),
			Categories:        categories,
			Commands:          commands,
			ExcludedCommands:  excludedCommands,
			Keys:              keys,
			Channels:          channels,
		}

		passwordHash := hashPassword(model.PasswordWo.ValueString())

		rules := buildACLRules(model, []string{passwordHash})

		assert.Contains(t, rules, "on")
		assert.Contains(t, rules, "reset")
		assert.Contains(t, rules, "+@read")
		assert.Contains(t, rules, "+@write")
		assert.Contains(t, rules, "+config|get")
		assert.Contains(t, rules, "-config|set")
		assert.Contains(t, rules, "~app:*")
		assert.Contains(t, rules, "&notifications:*")
	})
}

func TestToStringList(t *testing.T) {
	t.Run("converts list to string slice", func(t *testing.T) {
		list, _ := types.ListValueFrom(
			context.Background(),
			types.StringType,
			[]string{"value1", "value2", "value3"},
		)

		result := toStringList(list)

		require.Len(t, result, 3)
		assert.Equal(t, "value1", result[0].ValueString())
		assert.Equal(t, "value2", result[1].ValueString())
		assert.Equal(t, "value3", result[2].ValueString())
	})

	t.Run("handles null list", func(t *testing.T) {
		list := types.ListNull(types.StringType)

		result := toStringList(list)

		assert.Nil(t, result)
	})

	t.Run("handles unknown list", func(t *testing.T) {
		list := types.ListUnknown(types.StringType)

		result := toStringList(list)

		assert.Nil(t, result)
	})

	t.Run("handles empty list", func(t *testing.T) {
		list, _ := types.ListValueFrom(
			context.Background(),
			types.StringType,
			[]string{},
		)

		result := toStringList(list)

		assert.NotNil(t, result)
		assert.Len(t, result, 0)
	})
}

func TestToAny(t *testing.T) {
	t.Run("converts string slice to any slice", func(t *testing.T) {
		input := []string{"value1", "value2", "value3"}

		result := toAny(input)

		require.Len(t, result, 3)
		assert.Equal(t, "value1", result[0])
		assert.Equal(t, "value2", result[1])
		assert.Equal(t, "value3", result[2])
	})

	t.Run("converts int slice to any slice", func(t *testing.T) {
		input := []int{1, 2, 3}

		result := toAny(input)

		require.Len(t, result, 3)
		assert.Equal(t, 1, result[0])
		assert.Equal(t, 2, result[1])
		assert.Equal(t, 3, result[2])
	})

	t.Run("handles empty slice", func(t *testing.T) {
		input := []string{}

		result := toAny(input)

		assert.NotNil(t, result)
		assert.Len(t, result, 0)
	})
}

func TestRedisAclUserResource_redisClient(t *testing.T) {
	t.Run("creates redis client with correct configuration", func(t *testing.T) {
		r := &RedisAclUserResource{
			providerData: &RedisProviderModel{
				Address:  types.StringValue("localhost:6379"),
				Username: types.StringValue("admin"),
				Password: types.StringValue("secret"),
			},
		}

		client := r.redisClient()

		require.NotNil(t, client)
	})
}

func TestParseEnabledFromFlags(t *testing.T) {
	t.Run("returns true when 'on' flag is present", func(t *testing.T) {
		aclMap := map[string]any{
			"flags": []any{"on"},
		}

		result := parseEnabledFromFlags(aclMap)

		assert.True(t, result)
	})

	t.Run("returns false when 'off' flag is present", func(t *testing.T) {
		aclMap := map[string]any{
			"flags": []any{"off"},
		}

		result := parseEnabledFromFlags(aclMap)

		assert.False(t, result)
	})

	t.Run("returns true when 'on' is among multiple flags", func(t *testing.T) {
		aclMap := map[string]any{
			"flags": []any{"allkeys", "on", "allcommands"},
		}

		result := parseEnabledFromFlags(aclMap)

		assert.True(t, result)
	})

	t.Run("returns false when flags are missing", func(t *testing.T) {
		aclMap := map[string]any{
			"commands": "+@read",
		}

		result := parseEnabledFromFlags(aclMap)

		assert.False(t, result)
	})

	t.Run("returns false when flags is not a slice", func(t *testing.T) {
		aclMap := map[string]any{
			"flags": "on",
		}

		result := parseEnabledFromFlags(aclMap)

		assert.False(t, result)
	})

	t.Run("returns false when flags is empty", func(t *testing.T) {
		aclMap := map[string]any{
			"flags": []any{},
		}

		result := parseEnabledFromFlags(aclMap)

		assert.False(t, result)
	})

	t.Run("handles non-string flag values", func(t *testing.T) {
		aclMap := map[string]any{
			"flags": []any{123, true, "on"},
		}

		result := parseEnabledFromFlags(aclMap)

		assert.True(t, result)
	})
}

func TestParseCategoriesFromAclMap(t *testing.T) {
	t.Run("parses command categories with +@ prefix", func(t *testing.T) {
		aclMap := map[string]any{
			"commands": "+@read -config|set +@write +config|get +@admin",
		}

		categories, _, _ := parseCommandsFromAclMap(aclMap)

		assert.ElementsMatch(t, []string{"read", "write", "admin"}, categories)
	})

	t.Run("ignores commands with -@ prefix", func(t *testing.T) {
		aclMap := map[string]any{
			"commands": "+@read -config|set -@write +config|get +@admin",
		}

		categories, _, _ := parseCommandsFromAclMap(aclMap)

		assert.ElementsMatch(t, []string{"read", "admin"}, categories)
	})
}

func TestParseCommandsFromAclMap(t *testing.T) {
	t.Run("parses commands with + prefix", func(t *testing.T) {
		aclMap := map[string]any{
			"commands": "+@read -config|set +@write +config|get +@admin",
		}

		_, commands, _ := parseCommandsFromAclMap(aclMap)

		assert.ElementsMatch(t, []string{"config|get"}, commands)
	})

	t.Run("parses commands with - prefix", func(t *testing.T) {
		aclMap := map[string]any{
			"commands": "+@read -config|set +@write +config|get +@admin",
		}

		_, _, excludedCommands := parseCommandsFromAclMap(aclMap)

		assert.ElementsMatch(t, []string{"config|set"}, excludedCommands)
	})
}

func TestParseKeysFromAclMap(t *testing.T) {
	t.Run("parses regular keys with ~ prefix", func(t *testing.T) {
		aclMap := map[string]any{
			"keys": "~app:* ~user:*",
		}

		keys, readonlyKeys, writeonlyKeys := parseKeysFromAclMap(aclMap)

		assert.ElementsMatch(t, []string{"app:*", "user:*"}, keys)
		assert.Empty(t, readonlyKeys)
		assert.Empty(t, writeonlyKeys)
	})

	t.Run("parses readonly keys with %R~ prefix", func(t *testing.T) {
		aclMap := map[string]any{
			"keys": "%R~readonly:* %R~cache:*",
		}

		keys, readonlyKeys, writeonlyKeys := parseKeysFromAclMap(aclMap)

		assert.Empty(t, keys)
		assert.ElementsMatch(t, []string{"readonly:*", "cache:*"}, readonlyKeys)
		assert.Empty(t, writeonlyKeys)
	})

	t.Run("parses writeonly keys with %W~ prefix", func(t *testing.T) {
		aclMap := map[string]any{
			"keys": "%W~writeonly:* %W~logs:*",
		}

		keys, readonlyKeys, writeonlyKeys := parseKeysFromAclMap(aclMap)

		assert.Empty(t, keys)
		assert.Empty(t, readonlyKeys)
		assert.ElementsMatch(t, []string{"writeonly:*", "logs:*"}, writeonlyKeys)
	})

	t.Run("parses mixed key types", func(t *testing.T) {
		aclMap := map[string]any{
			"keys": "~app:* %R~readonly:* %W~writeonly:*",
		}

		keys, readonlyKeys, writeonlyKeys := parseKeysFromAclMap(aclMap)

		assert.Equal(t, []string{"app:*"}, keys)
		assert.Equal(t, []string{"readonly:*"}, readonlyKeys)
		assert.Equal(t, []string{"writeonly:*"}, writeonlyKeys)
	})

	t.Run("handles non-string key values", func(t *testing.T) {
		aclMap := map[string]any{
			"keys": "~app:* 123 ~user:*",
		}

		keys, readonlyKeys, writeonlyKeys := parseKeysFromAclMap(aclMap)

		assert.ElementsMatch(t, []string{"app:*", "user:*"}, keys)
		assert.Empty(t, readonlyKeys)
		assert.Empty(t, writeonlyKeys)
	})

	t.Run("handles keys without recognized prefixes", func(t *testing.T) {
		aclMap := map[string]any{
			"keys": "noprefix ~app:*",
		}

		keys, readonlyKeys, writeonlyKeys := parseKeysFromAclMap(aclMap)

		assert.Equal(t, []string{"app:*"}, keys)
		assert.Empty(t, readonlyKeys)
		assert.Empty(t, writeonlyKeys)
	})
}

func TestParseChannelsFromAclMap(t *testing.T) {
	t.Run("parses channels with & prefix", func(t *testing.T) {
		aclMap := map[string]any{
			"channels": "&notifications:* &alerts:*",
		}

		channels := parseChannelsFromAclMap(aclMap)

		assert.ElementsMatch(t, []string{"notifications:*", "alerts:*"}, channels)
	})

	t.Run("ignores channels without & prefix", func(t *testing.T) {
		aclMap := map[string]any{
			"channels": "noprefix &notifications:*",
		}

		channels := parseChannelsFromAclMap(aclMap)

		assert.Equal(t, []string{"notifications:*"}, channels)
	})

	t.Run("handles non-string channel values", func(t *testing.T) {
		aclMap := map[string]any{
			"channels": "&notifications:* 123 &alerts:*",
		}

		channels := parseChannelsFromAclMap(aclMap)

		assert.ElementsMatch(t, []string{"notifications:*", "alerts:*"}, channels)
	})
}

func TestConvertToTypesList(t *testing.T) {
	t.Run("converts string slice to types.List", func(t *testing.T) {
		ctx := context.Background()
		diags := &diag.Diagnostics{}
		items := []string{"item1", "item2", "item3"}

		result, err := convertToTypesList(ctx, items, diags)

		assert.NoError(t, err)
		assert.False(t, result.IsNull())
		assert.False(t, diags.HasError())

		var output []string
		result.ElementsAs(ctx, &output, false)
		assert.ElementsMatch(t, []string{"item1", "item2", "item3"}, output)
	})

	t.Run("converts single item slice", func(t *testing.T) {
		ctx := context.Background()
		diags := &diag.Diagnostics{}
		items := []string{"single"}

		result, err := convertToTypesList(ctx, items, diags)

		assert.NoError(t, err)
		assert.False(t, result.IsNull())

		var output []string
		result.ElementsAs(ctx, &output, false)
		assert.Equal(t, []string{"single"}, output)
	})
}

func TestLoadAclMapIntoState(t *testing.T) {
	t.Run("loads all ACL data into state", func(t *testing.T) {
		ctx := context.Background()
		diags := &diag.Diagnostics{}
		aclMap := map[string]any{
			"flags":    []any{"on"},
			"commands": "+@read +@write",
			"keys":     "~app:* %R~readonly:* %W~writeonly:*",
			"channels": "&notifications:*",
		}
		state := &RedisAclUserResourceModel{
			Name: types.StringValue("testuser"),
		}

		err := loadAclMapIntoState(ctx, aclMap, state, diags)

		assert.NoError(t, err)
		assert.False(t, diags.HasError())
		assert.True(t, state.Enabled.ValueBool())
		assert.False(t, state.Commands.IsNull())
		assert.False(t, state.Keys.IsNull())
		assert.False(t, state.ReadonlyKeys.IsNull())
		assert.False(t, state.WriteonlyKeys.IsNull())
		assert.False(t, state.Channels.IsNull())
	})

	t.Run("handles disabled user", func(t *testing.T) {
		ctx := context.Background()
		diags := &diag.Diagnostics{}
		aclMap := map[string]any{
			"flags": []any{"off"},
		}
		state := &RedisAclUserResourceModel{
			Name: types.StringValue("testuser"),
		}

		err := loadAclMapIntoState(ctx, aclMap, state, diags)

		assert.NoError(t, err)
		assert.False(t, state.Enabled.ValueBool())
	})

	t.Run("handles missing optional fields", func(t *testing.T) {
		ctx := context.Background()
		diags := &diag.Diagnostics{}
		aclMap := map[string]any{
			"flags": []any{"on"},
		}
		state := &RedisAclUserResourceModel{
			Name: types.StringValue("testuser"),
		}

		err := loadAclMapIntoState(ctx, aclMap, state, diags)

		assert.NoError(t, err)
		assert.True(t, state.Enabled.ValueBool())
	})

	t.Run("handles empty ACL map", func(t *testing.T) {
		ctx := context.Background()
		diags := &diag.Diagnostics{}
		aclMap := map[string]any{}
		state := &RedisAclUserResourceModel{
			Name: types.StringValue("testuser"),
		}

		err := loadAclMapIntoState(ctx, aclMap, state, diags)

		assert.NoError(t, err)
		assert.False(t, state.Enabled.ValueBool())
	})
}

func TestStringInList(t *testing.T) {
	t.Run("finds string in list", func(t *testing.T) {
		list := []types.String{
			types.StringValue("value1"),
			types.StringValue("value2"),
			types.StringValue("value3"),
		}

		result := stringInList("value2", list)

		assert.True(t, result)
	})

	t.Run("returns false when string not in list", func(t *testing.T) {
		list := []types.String{
			types.StringValue("value1"),
			types.StringValue("value2"),
		}

		result := stringInList("value3", list)

		assert.False(t, result)
	})

	t.Run("returns false for empty list", func(t *testing.T) {
		list := []types.String{}

		result := stringInList("value", list)

		assert.False(t, result)
	})

	t.Run("returns false for nil list", func(t *testing.T) {
		var list []types.String

		result := stringInList("value", list)

		assert.False(t, result)
	})

	t.Run("handles case-sensitive matching", func(t *testing.T) {
		list := []types.String{
			types.StringValue("Value1"),
			types.StringValue("value2"),
		}

		assert.True(t, stringInList("Value1", list))
		assert.False(t, stringInList("value1", list))
	})
}

func BenchmarkBuildACLRules(b *testing.B) {
	commands, _ := types.ListValueFrom(
		context.Background(),
		types.StringType,
		[]string{"get", "set"},
	)
	keys, _ := types.ListValueFrom(
		context.Background(),
		types.StringType,
		[]string{"app:*"},
	)
	channels, _ := types.ListValueFrom(
		context.Background(),
		types.StringType,
		[]string{"notifications:*"},
	)

	model := &RedisAclUserResourceModel{
		Name:              types.StringValue("testuser"),
		Enabled:           types.BoolValue(true),
		PasswordWo:        types.StringValue("mypassword"),
		PasswordWoVersion: types.StringValue("v1"),
		Commands:          commands,
		Keys:              keys,
		Channels:          channels,
	}

	b.ResetTimer()

	passwordHash := hashPassword(model.PasswordWo.ValueString())

	for i := 0; i < b.N; i++ {
		buildACLRules(model, []string{passwordHash})
	}
}

func BenchmarkParseEnabledFromFlags(b *testing.B) {
	aclMap := map[string]any{
		"flags": []any{"allkeys", "on", "allcommands"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseEnabledFromFlags(aclMap)
	}
}

func BenchmarkParseCommandsFromAclMap(b *testing.B) {
	aclMap := map[string]any{
		"commands": "+@read +@write +@admin +@dangerous +@keyspace",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseCommandsFromAclMap(aclMap)
	}
}

func BenchmarkParseKeysFromAclMap(b *testing.B) {
	aclMap := map[string]any{
		"keys": "~app:* ~user:* %R~readonly:* %R~cache:* %W~writeonly:* %W~logs:*",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseKeysFromAclMap(aclMap)
	}
}

func BenchmarkParseChannelsFromAclMap(b *testing.B) {
	aclMap := map[string]any{
		"channels": "&notifications:* &alerts:* &events:* &messages:*",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseChannelsFromAclMap(aclMap)
	}
}

func BenchmarkLoadAclMapIntoState(b *testing.B) {
	ctx := context.Background()
	diags := &diag.Diagnostics{}
	aclMap := map[string]any{
		"flags":    []any{"on"},
		"commands": "+@read +@write",
		"keys":     "~app:* %R~readonly:* %W~writeonly:*",
		"channels": "&notifications:*",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := &RedisAclUserResourceModel{
			Name: types.StringValue("testuser"),
		}
		loadAclMapIntoState(ctx, aclMap, state, diags)
	}
}
