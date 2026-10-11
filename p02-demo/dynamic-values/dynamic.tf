variable "extra_actions" {
  type = list(string)
}

resource "aws_iam_policy" "variable_actions" {
  name = "variable-actions"
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = var.extra_actions
      Resource = "*"
    }]
  })
}

resource "aws_security_group" "maybe_public" {
  name = "maybe-public"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  dynamic "ingress" {
    for_each = var.extra_rules
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = ingress.value.cidrs
    }
  }
}
