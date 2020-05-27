terraform {
  backend "s3" {
    bucket = "dfdssharedprodecr"
    key    = "ecrstate-v2"
    region = "eu-central-1"
  }
}

provider "aws" {
  region  = var.aws_region
  version = "~> 2.43"
}

