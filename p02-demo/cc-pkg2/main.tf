resource "aws_security_group" "bastion" {
  name = "bastion"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.168.10.0/24"]
  }

  ingress {
    from_port   = 80
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "rdp_v6" {
  type              = "ingress"
  security_group_id = "sg-example"
  from_port         = 3000
  to_port           = 4000
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"]
}

resource "aws_vpc_security_group_ingress_rule" "everything" {
  security_group_id = "sg-example"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_security_group_rule" "outbound" {
  type              = "egress"
  security_group_id = "sg-example"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_vpc_security_group_ingress_rule" "public_dns" {
  security_group_id = "sg-example"
  ip_protocol       = "udp"
  from_port         = 53
  to_port           = 53
  cidr_ipv4         = "0.0.0.0/0"
}
