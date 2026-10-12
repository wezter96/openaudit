provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAEXAMPLEEXAMPLE00"
  secret_key = "not-a-real-secret-key-example-value"
}

resource "aws_s3_bucket" "site" {
  bucket = "my-site"
  acl    = "public-read"
}

resource "aws_security_group" "ssh" {
  name = "ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = "SuperSecret123-not-real"
  publicly_accessible = true
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}

resource "aws_iam_policy" "admin" {
  name = "admin"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
POLICY
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = "assets"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "azurerm_storage_account" "sa" {
  name                            = "sa"
  allow_nested_items_to_be_public = true
}

resource "aws_cloudtrail" "trail" {
  name           = "trail"
  enable_logging = false
}
