provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAQ3EGRQFAKE7DEMO1"
}

resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  acl    = "public-read"
}

resource "aws_db_instance" "main" {
  publicly_accessible = true
  storage_encrypted   = false
}
