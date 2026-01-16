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
