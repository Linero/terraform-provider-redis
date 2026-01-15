ephemeral "redis_acl_user" "user" {
  mount        = "secret"
  name         = "my/secret"
  password_len = 32
}
