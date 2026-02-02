# Terraform Provider Redis

This custom Terraform provider allows you to manage Redis ACL users.

## Provider Configuration

The provider requires the Redis address and credentials.

```hcl
provider "redis" {
  address  = "localhost:6379"
  username = "default"
  password = "mypassword"
}
```

## Resources

### Resource: `redis_acl_user`

This resource manages a Redis ACL user.

#### Arguments

* `name` (String, Required) Name of the ACL user.
* `password_wo` (String, Required, Sensitive, Write-only) Write-only password for the ACL user. The provider hashes this password with SHA256 before storing it in Redis.
* `password_wo_version` (String, Required) Version string for the password. Changing this value forces a password update (and resource update) even if `password_wo` hasn't changed in the configuration. Use this to trigger rotation.
* `enabled` (Boolean, Optional) Whether the ACL user is enabled. Defaults to `true`.
* `categories` (List of String, Optional) ACL command categories for the user (e.g., `read`, `write`, `admin`, `pubsub`).
* `commands` (List of String, Optional) ACL commands for the user (e.g., 'config|get', 'keys', 'all').
* `excluded_commands` (List of String, Optional) ACL commands to exclude for the user (e.g., 'config|get', 'keys', 'all').
* `keys` (List of String, Optional) Key patterns the user can access.
* `readonly_keys` (List of String, Optional) Key patterns the user can only read.
* `writeonly_keys` (List of String, Optional) Key patterns the user can only write.
* `channels` (List of String, Optional) Pub/Sub channel patterns the user can access.
* `acl_save` (Boolean, Optional) Whether to save the ACL configuration to the disk on the Redis server after changes. Defaults to `true`.

## Installation

To build the provider from source and register it for local use with Terraform, you can use the included script or follow these steps:

### Using the install script

```bash
./install_provider.sh
```

### Manual Build

```bash
# Set version and platform variables
VERSION=0.0.0-dev # Or your git tag
PLATFORM=$(uname -s | tr 'A-Z' 'a-z')_$(uname -m)
# Adjust arch if needed (e.g., amd64 for x86_64)

# Create the local plugin directory
mkdir -p $HOME/.terraform.d/plugins/registry.terraform.io/linero/redis/$VERSION/$PLATFORM

# Build the provider and move it to the plugin directory
go build -o $HOME/.terraform.d/plugins/registry.terraform.io/linero/redis/$VERSION/$PLATFORM/terraform-provider-redis_v$VERSION
```

After building, you can reference the provider in your Terraform configuration:

```hcl
terraform {
  required_providers {
    redis = {
      source  = "registry.terraform.io/linero/redis"
      version = "0.0.0-dev" # Match the version built
    }
  }
}
```

## Example Usage

```hcl
resource "redis_acl_user" "example" {
  name                = "example-user"
  enabled             = true
  password_wo         = "strong-password"
  password_wo_version = "v1"

  categories = ["read", "write", "pubsub"]
  commands   = ["config|get"]
  keys       = ["app:*", "cache:*"]
  channels   = ["notifications"]
}
```
