terraform {
  required_version = ">= 0.13.1"

  required_providers {
    null = {
      source  = "hashicorp/null"
      version = ">=3.1"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.8"
    }
  }
}
