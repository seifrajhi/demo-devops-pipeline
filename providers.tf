terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.57.0"
    }

    http = {
      source  = "hashicorp/http"
      version = "~> 2.1.0"
    }
  }
}

data "aws_region" "current" {
}

data "aws_availability_zones" "available" {
}
