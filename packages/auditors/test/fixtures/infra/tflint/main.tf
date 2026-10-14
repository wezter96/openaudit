terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

variable "name" {}

variable "unused" {
  type    = string
  default = "x"
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t9.mega"
  tags = {
    Name = "${var.name}"
  }
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
}

module "gcp" {
  source = "./modules/gcp"
}
