---
page_title: "Redis Provider"
description: |-
  The redis provider allows managing redis acl users.
---

# Redis Provider

The Redis provider provides resources to interact with a Redis server, specifically for managing ACL users.

## Example Usage

```terraform
provider "redis" {
  address  = "localhost:6379"
  username = "default"
  password = "mypassword"
}
```

## Schema

### Required

- `address` (String) The address of the Redis server (e.g., `localhost:6379`).
- `password` (String, Sensitive) The password for the Redis user.
- `username` (String, Sensitive) The username for the Redis user.