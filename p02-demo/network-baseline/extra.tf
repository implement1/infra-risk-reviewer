# Example only: never allow Action "*" on Resource "*" or 0.0.0.0/0 on port 22.
resource "aws_iam_policy" "reader" {
  name        = "artifact-reader"
  description = "Grants s3:GetObject only; not Action * or Resource *"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = ["arn:aws:s3:::example-artifacts", "arn:aws:s3:::example-artifacts/*"]
      },
      {
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
      },
    ]
  })
}

resource "aws_security_group" "web" {
  name = "web-tier"

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from the private admin range only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Note = "port 22 open to 0.0.0.0/0 is forbidden here"
  }
}
