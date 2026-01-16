---
page_title: "redis_acl_user Resource - redis"
description: |-
  Resource to create and manage a Redis ACL user.
---

# redis_acl_user (Resource)

The `redis_acl_user` resource manages Redis ACL users. It allows you to define users, their passwords, and their permissions (commands, keys, channels).

## Example Usage

```terraform
resource "redis_acl_user" "example" {
  name                = "myuser"
  enabled             = true
  password_wo         = "strongpassword123"
  password_wo_version = "1"
  commands            = ["read", "write", "pubsub"]
  keys                = ["app:*", "cache:*"]
  readonly_keys       = ["readonly:*"]
  writeonly_keys      = ["writeonly:*"]
  channels            = ["notifications:*"]
  acl_save            = true
}
```

## Schema

### Required

- `name` (String) Name of the ACL user.
- `password_wo` (String, Sensitive) Write-only password for the ACL user. The provider hashes this password with SHA256 before being stored in Redis.
- `password_wo_version` (String) Version string for password. Changing this value forces a password update even if `password_wo` hasn't changed in the configuration. Use this to rotate passwords.

### Optional

- `acl_save` (Boolean) Whether to save the ACL user configuration to the disk on the Redis server. Defaults to `true`.
- `channels` (List of String) Pub/Sub channel patterns the user can access (without `&` prefix).
- `commands` (List of String) ACL command categories for the user (e.g., 'read', 'write', 'admin', 'pubsub'). Do not include `+@` or `-@` prefixes.
- `enabled` (Boolean) Whether the ACL user is enabled. Defaults to `true`.
- `keys` (List of String) Key patterns the user can access (without `~` prefix).
- `readonly_keys` (List of String) Key patterns the user can only read (without `%R~` prefix).
- `writeonly_keys` (List of String) Key patterns the user can only write (without `%W~` prefix).

### Read-Only

- `id` (String) The ID of this resource.

## Import

Import is supported using the following syntax:

```shell
# ACL users can be imported using the user name
terraform import redis_acl_user.example myuser
```