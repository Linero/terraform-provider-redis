terraform {
  required_providers {
    redis = {
      source  = "registry.terraform.io/linero/redis"
      version = "0.0.0-dev"
    }
  }
}
provider "redis" {
  address  = "localhost:6379"
  username = "testuser"
  password = "supersecretpassword"
}

ephemeral "random_password" "password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "redis_acl_user" "user" {
  name                = "newuser"
  password_wo         = ephemeral.random_password.password.result
  password_wo_version = "2"
  categories          = ["write", "read", "pubsub"]
  commands            = ["config|get"]
  excluded_commands   = ["config|set"]
  keys                = ["app:*"]
  readonly_keys       = ["readonly:*"]
  writeonly_keys      = ["writeonly:*"]
  channels            = ["notifications:*"]
  acl_save            = false
}
