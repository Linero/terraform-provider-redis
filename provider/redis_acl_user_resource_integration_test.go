package provider

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func TestAclSetUser_Integration(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}
	t.Run("creates new acl user in redis", func(t *testing.T) {
		req := resource.ConfigureRequest{
			ProviderData: &RedisProviderModel{
				Address:  types.StringValue("localhost:6379"),
				Username: types.StringValue("testuser"),
				Password: types.StringValue("supersecretpassword"),
			},
		}
		resp := &resource.ConfigureResponse{}
		r := &RedisAclUserResource{}
		r.Configure(context.Background(), req, resp)

		commands, _ := types.ListValueFrom(context.Background(), types.StringType, []string{"read", "write", "pubsub"})
		keys, _ := types.ListValueFrom(context.Background(), types.StringType, []string{"app:*"})
		readonlyKeys, _ := types.ListValueFrom(context.Background(), types.StringType, []string{"readonly:*"})
		writeonlyKeys, _ := types.ListValueFrom(context.Background(), types.StringType, []string{"writeonly:*"})
		channels, _ := types.ListValueFrom(context.Background(), types.StringType, []string{"notifications:*"})

		model := &RedisAclUserResourceModel{
			Name:              types.StringValue("newuser"),
			Enabled:           types.BoolValue(true),
			PasswordWo:        types.StringValue("userpassword"),
			PasswordWoVersion: types.StringValue("1"),
			Commands:          commands,
			Keys:              keys,
			ReadonlyKeys:      readonlyKeys,
			WriteonlyKeys:     writeonlyKeys,
			Channels:          channels,
			AclSave:           types.BoolValue(false),
		}

		passwordHash := hashPassword(model.PasswordWo.ValueString())

		result, err := r.AclSetUser(model, context.Background(), []string{passwordHash})

		assert.Equal(t, err, nil)
		assert.Equal(t, true, result)
	})
}

func TestAclGetUser_Integration(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}
	t.Run("retrieves existing acl user from redis", func(t *testing.T) {
		req := resource.ConfigureRequest{
			ProviderData: &RedisProviderModel{
				Address:  types.StringValue("localhost:6379"),
				Username: types.StringValue("testuser"),
				Password: types.StringValue("supersecretpassword"),
			},
		}
		resp := &resource.ConfigureResponse{}
		r := &RedisAclUserResource{}
		r.Configure(context.Background(), req, resp)

		aclData, err := r.AclGetUser("newuser", context.Background())
		aclMap := parseAclDataToMap(aclData)

		commands := parseCommandsFromAclMap(aclMap)
		channels := parseChannelsFromAclMap(aclMap)
		enabled := parseEnabledFromFlags(aclMap)
		keys, readonlyKeys, writeonlyKeys := parseKeysFromAclMap(aclMap)

		assert.Equal(t, err, nil)
		assert.NotNil(t, aclMap)
		assert.Contains(t, commands, "read")
		assert.Contains(t, commands, "write")
		assert.Contains(t, channels, "notifications:*")
		assert.Equal(t, true, enabled)
		assert.Contains(t, keys, "app:*")
		assert.Contains(t, readonlyKeys, "readonly:*")
		assert.Contains(t, writeonlyKeys, "writeonly:*")
	})
}

func TestLoadAclMapIntoState_Integration(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}
	t.Run("loads acl map into resource state", func(t *testing.T) {
		req := resource.ConfigureRequest{
			ProviderData: &RedisProviderModel{
				Address:  types.StringValue("localhost:6379"),
				Username: types.StringValue("testuser"),
				Password: types.StringValue("supersecretpassword"),
			},
		}
		resp := &resource.ConfigureResponse{}
		r := &RedisAclUserResource{}
		r.Configure(context.Background(), req, resp)
		state := &RedisAclUserResourceModel{}

		aclData, err := r.AclGetUser("newuser", context.Background())
		aclMap := parseAclDataToMap(aclData)
		loadAclMapIntoState(context.Background(), aclMap, state, &diag.Diagnostics{})

		assert.Equal(t, err, nil)
		assert.Equal(t, true, state.Enabled.ValueBool())
		assert.False(t, state.Commands.IsNull())
		assert.False(t, state.Keys.IsNull())
		assert.False(t, state.ReadonlyKeys.IsNull())
		assert.False(t, state.WriteonlyKeys.IsNull())
		assert.False(t, state.Channels.IsNull())

	})
}

func TestAclDelUser_Integration(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}
	t.Run("retrieves existing acl user from redis", func(t *testing.T) {
		req := resource.ConfigureRequest{
			ProviderData: &RedisProviderModel{
				Address:  types.StringValue("localhost:6379"),
				Username: types.StringValue("testuser"),
				Password: types.StringValue("supersecretpassword"),
			},
		}
		resp := &resource.ConfigureResponse{}
		r := &RedisAclUserResource{}
		r.Configure(context.Background(), req, resp)

		result, err := r.AclDelUser("newuser", context.Background(), false)

		assert.Equal(t, err, nil)
		assert.Equal(t, true, result)
	})
}
