resource "aws_iam_policy" "break_glass" {
  name = "break-glass-admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "bucket_ops" {
  role   = "bucket-operator"
  policy = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::example-reports/*"}
      ]
    }
  EOT
}

data "aws_iam_policy_document" "conditional_admin" {
  statement {
    actions   = ["*"]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_policy" "from_document" {
  name   = "conditional-admin"
  policy = data.aws_iam_policy_document.conditional_admin.json
}
