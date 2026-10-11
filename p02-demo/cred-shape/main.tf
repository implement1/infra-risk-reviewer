resource "aws_s3_bucket" "logs" {
  bucket = "synthetic-logs"
  tags = {
    note = "-----BEGIN RSA PRIVATE KEY-----"
  }
}
