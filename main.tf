terraform {
  backend "s3" {
    bucket = "dfdssharedprodecr"
    key    = "ecrscanstate"
    region = "eu-central-1"
  }
}

provider "aws" {
  region  = var.aws_region
  version = "~> 4.0"
}

